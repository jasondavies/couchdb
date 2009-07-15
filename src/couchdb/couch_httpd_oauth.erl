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
oauth_authentication_handler(#httpd{mochi_req=MochiReq, method=Method, req_body=ReqBody}=Req) ->
    Req2 = case ReqBody of
        undefined -> Req#httpd{req_body=MochiReq:recv_body()};
        _Else -> Req
    end,
    case serve_oauth(Req2, fun(URL, Params, Consumer, Signature) ->
        case oauth:verify(Signature, Method, URL, Params, Consumer, "") of
            true ->
                set_user_ctx(Req2, Consumer);
            false -> Req2
        end
    end) of
        undefined -> Req2;
        #httpd{}=Req3 -> Req3;
        Resp -> {ok, Resp}
    end.

set_user_ctx(Req, {ConsumerKey, _Secret, _SignatureMethod}) ->
    Req#httpd{user_ctx=#user_ctx{name=?l2b(ConsumerKey), roles=[<<"_admin">>]}}.

handle_oauth_req(#httpd{path_parts=[_OAuth, <<"request_token">>]}=Req) ->
    {ok, serve_oauth_request_token(Req)};
handle_oauth_req(#httpd{path_parts=[_OAuth, <<"authorize">>]}=Req) ->
    {ok, serve_oauth_authorize(Req)};
handle_oauth_req(#httpd{path_parts=[_OAuth, <<"access_token">>]}=Req) ->
    {ok, serve_oauth_access_token(Req)}.

serve_oauth_request_token(#httpd{method=Method}=Req) ->
    case Method of
        'GET' ->
            serve_oauth(Req, fun(URL, Params, Consumer, Signature) ->
                case oauth:verify(Signature, "GET", URL, Params, Consumer, "") of
                    true ->
                        ok(Req, <<"oauth_token=requestkey&oauth_token_secret=requestsecret">>);
                    false ->
                        bad(Req, "Invalid signature value.")
                end
            end);
        'POST' ->
            serve_oauth(Req, fun(URL, Params, Consumer, Signature) ->
                case oauth:verify(Signature, "POST", URL, Params, Consumer, "") of
                    true ->
                        ok(Req, <<"oauth_token=requestkey&oauth_token_secret=requestsecret">>);
                    false ->
                        bad(Req, "Invalid signature value.")
                end
            end);
        _ ->
            method_not_allowed(Req)
    end.

% This needs to be protected i.e. force user to login using HTTP Basic Auth or form-based login.
serve_oauth_authorize(#httpd{method=Method}=Req) ->
    case Method of
        'GET' ->
            % Confirm with the User that they want to authenticate the Consumer
            serve_oauth(Req, fun(URL, Params, Consumer, Signature) ->
                case oauth:verify(Signature, "GET", URL, Params, Consumer, "") of
                    true ->
                        ok(Req, <<"oauth_token=requestkey&oauth_token_secret=requestsecret">>);
                    false ->
                        bad(Req, "Invalid signature value.")
                end
            end);
        'POST' ->
            % If the User has confirmed, we direct the User back to the Consumer with a verification code
            serve_oauth(Req, fun(URL, Params, Consumer, Signature) ->
                case oauth:verify(Signature, "POST", URL, Params, Consumer, "") of
                    true ->
                        %redirect(oauth_callback, oauth_token, oauth_verifier),
                        ok(Req, <<"oauth_token=requestkey&oauth_token_secret=requestsecret">>);
                    false ->
                        bad(Req, "Invalid signature value.")
                end
            end);
        _ ->
            method_not_allowed(Req)
    end.

serve_oauth_access_token(#httpd{method=Method}=Req) ->
    case Method of
        'GET' ->
            serve_oauth(Req, fun(URL, Params, Consumer, Signature) ->
                case oauth:token(Params) of
                    "requestkey" ->
                        case oauth:verify(Signature, "GET", URL, Params, Consumer, "requestsecret") of
                            true ->
                                ok(Req, <<"oauth_token=accesskey&oauth_token_secret=accesssecret">>);
                            false ->
                                bad(Req, "Invalid signature value.")
                        end;
                    _ ->
                        bad(Req, "Invalid OAuth token.")
                end
            end);
        _ ->
            method_not_allowed(Req)
    end.

serve_oauth(#httpd{mochi_req=MochiReq, req_body=ReqBody, method=Method}=Req, Fun) ->
    % 1. In the HTTP Authorization header as defined in OAuth HTTP Authorization Scheme.
    % 2. As the HTTP POST request body with a content-type of application/x-www-form-urlencoded.
    % 3. Added to the URLs in the query part (as defined by [RFC3986] section 3).
    AuthorizationHeader = MochiReq:get_header_value("authorization"),
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
            case Method of
                "POST" ->
                    case MochiReq:get_primary_header_value("content-type") of
                        "application/x-www-form-urlencoded" ++ _ ->
                            mochiweb_util:parse_qs(ReqBody);
                        _ ->
                            MochiReq:parse_qs()
                    end;
                _OtherMethod ->
                    MochiReq:parse_qs()
            end;
        HeaderString ->
            ?LOG_DEBUG("OAuth Header: ~p", [HeaderString]),
            oauth_uri:params_from_header_string(HeaderString)
    end,
    ?LOG_DEBUG("OAuth Params: ~p", [Params]),
    case get_value("oauth_version", Params, "1.0") of
        "1.0" ->
            case get_value("oauth_consumer_key", Params, undefined) of
                undefined -> undefined;
                ConsumerKey ->
                    SigMethod = get_value("oauth_signature_method", Params),
                    case consumer_lookup(ConsumerKey, SigMethod) of
                        none ->
                            bad(Req, "Invalid consumer (key or signature method).");
                        Consumer ->
                            Signature = proplists:get_value("oauth_signature", Params),
                            URL = string:concat("http://0.0.0.0:8000", MochiReq:get(path)),
                            Fun(URL, proplists:delete("oauth_signature", Params), Consumer, Signature)
                    end
            end;
        _ ->
            bad(Req, "Invalid OAuth version.")
    end.

consumer_lookup("key", "PLAINTEXT") ->
    {"key", "secret", plaintext};
consumer_lookup("key", "HMAC-SHA1") ->
    {"key", "secret", hmac_sha1};
consumer_lookup("key", "RSA-SHA1") ->
    {"key", "data/rsa_cert.pem", rsa_sha1};
consumer_lookup(_, _) ->
    none.

ok(#httpd{mochi_req=MochiReq}, Body) ->
    MochiReq:respond({200, [], Body}).

bad(#httpd{mochi_req=MochiReq}, Reason) ->
    MochiReq:respond({400, [], list_to_binary("Bad Request: " ++ Reason)}).

method_not_allowed(#httpd{mochi_req=MochiReq}) ->
    MochiReq:respond({405, [], <<>>}).
