% Licensed under the Apache License, Version 2.0 (the "License"); you may not
% use this file except in compliance with the License.  You may obtain a copy of
% the License at
%
%   http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
% WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
% License for the specific language governing permissions and limitations under
% the License.

-module(couch_httpd_oauth).
-include("couch_db.hrl").

-export([oauth_authentication_handler/1, handle_oauth_req/1]).

-import(couch_httpd, [header_value/2, send_json/4, send_method_not_allowed/2]).
-import(erlang, [integer_to_list/2, list_to_integer/2]).
-import(proplists, [get_value/2, get_value/3]).

% OAuth auth handler using per-node user db
oauth_authentication_handler(Req) ->
    DbName = couch_config:get("couch_httpd_auth", "authentication_db"),
    Req#httpd{user_ctx=#user_ctx{roles=[<<"_admin">>]}}.

handle_oauth_req(#httpd{path_parts=[_OAuth, <<"request_token">>], mochi_req=MochiReq}=Req) ->
    serve_oauth_request_token(MochiReq);
handle_oauth_req(#httpd{path_parts=[_OAuth, <<"access_token">>], mochi_req=MochiReq}=Req) ->
    serve_oauth_access_token(MochiReq).

serve_oauth_request_token(Request) ->
    case Request:get(method) of
        'GET' ->
            serve_oauth(Request, fun(URL, Params, Consumer, Signature) ->
                case oauth:verify(Signature, "GET", URL, Params, Consumer, "") of
                    true ->
                        ok(Request, <<"oauth_token=requestkey&oauth_token_secret=requestsecret">>);
                    false ->
                        bad(Request, "Invalid signature value.")
                end
            end);
        'POST' ->
            serve_oauth(Request, fun(URL, Params, Consumer, Signature) ->
                case oauth:verify(Signature, "POST", URL, Params, Consumer, "") of
                    true ->
                        ok(Request, <<"oauth_token=requestkey&oauth_token_secret=requestsecret">>);
                    false ->
                        bad(Request, "Invalid signature value.")
                end
            end);
        _ ->
            method_not_allowed(Request)
    end.

serve_oauth_access_token(Request) ->
    case Request:get(method) of
        'GET' ->
            serve_oauth(Request, fun(URL, Params, Consumer, Signature) ->
                case oauth:token(Params) of
                    "requestkey" ->
                        case oauth:verify(Signature, "GET", URL, Params, Consumer, "requestsecret") of
                            true ->
                                ok(Request, <<"oauth_token=accesskey&oauth_token_secret=accesssecret">>);
                            false ->
                                bad(Request, "Invalid signature value.")
                        end;
                    _ ->
                        bad(Request, "Invalid OAuth token.")
                end
            end);
        _ ->
            method_not_allowed(Request)
    end.

serve_echo(Request) ->
    case Request:get(method) of
        'GET' ->
            serve_oauth(Request, fun(URL, Params, Consumer, Signature) ->
                case oauth:token(Params) of
                    "accesskey" ->
                        case oauth:verify(Signature, "GET", URL, Params, Consumer, "accesssecret") of
                            true ->
                                EchoParams = lists:filter(fun({K, _}) -> not lists:prefix("oauth_", K) end, Params),
                                ok(Request, oauth_uri:params_to_string(EchoParams));
                            false ->
                                bad(Request, "Invalid signature value.")
                        end;
                    _ ->
                        bad(Request, "Invalid OAuth token.")
                end
            end);
        _ ->
            method_not_allowed(Request)
    end.
 
serve_oauth(Request, Fun) ->
    % 1. In the HTTP Authorization header as defined in OAuth HTTP Authorization Scheme.
    % 2. As the HTTP POST request body with a content-type of application/x-www-form-urlencoded.
    % 3. Added to the URLs in the query part (as defined by [RFC3986] section 3).
    AuthorizationHeader = Request:get_header_value("authorization"),
    OAuthHeader = case AuthorizationHeader of
        undefined ->
            undefined;
        Else ->
            [Head | Tail] = re:split(Else, "\\s", [{parts, 2}, {return, list}]),
            case string:to_lower(Head) of
                "oauth" -> [Rest] = Tail, Rest;
                _Else -> undefined
            end
    end,
    Params = case OAuthHeader of 
        undefined ->
            case Request:get(method) of
                'POST' ->
                    case Request:get_primary_header_value("content-type") of
                        "application/x-www-form-urlencoded" ++ _ ->
                            mochiweb_util:parse_qs(Request:recv_body());
                        _ ->
                            Request:parse_qs()
                    end;
                _OtherMethod ->
                    Request:parse_qs()
            end;
        HeaderString ->
            ?LOG_DEBUG("OAuth Header: ~p", [HeaderString]),
            oauth_uri:params_from_header_string(HeaderString)
    end,
    ?LOG_DEBUG("OAuth Params: ~p", [Params]),
    case get_value("oauth_version", Params, "1.0") of
        "1.0" ->
            ConsumerKey = get_value("oauth_consumer_key", Params),
            SigMethod = get_value("oauth_signature_method", Params),
            case consumer_lookup(ConsumerKey, SigMethod) of
                none ->
                    bad(Request, "Invalid consumer (key or signature method).");
                Consumer ->
                    Signature = proplists:get_value("oauth_signature", Params),
                    URL = string:concat("http://0.0.0.0:8000", Request:get(path)),
                    Fun(URL, proplists:delete("oauth_signature", Params), Consumer, Signature)
            end;
        _ ->
            bad(Request, "Invalid OAuth version.")
    end.

consumer_lookup("key", "PLAINTEXT") ->
    {"key", "secret", plaintext};
consumer_lookup("key", "HMAC-SHA1") ->
    {"key", "secret", hmac_sha1};
consumer_lookup("key", "RSA-SHA1") ->
    {"key", "data/rsa_cert.pem", rsa_sha1};
consumer_lookup(_, _) ->
    none.

ok(Request, Body) ->
    Request:respond({200, [], Body}).

bad(Request, Reason) ->
    Request:respond({400, [], list_to_binary("Bad Request: " ++ Reason)}).

method_not_allowed(Request) ->
    Request:respond({405, [], <<>>}).
