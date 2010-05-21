% Licensed under the Apache License, Version 2.0 (the "License"); you may not
% use this file except in compliance with the License. You may obtain a copy of
% the License at
%
%   http://www.apache.org/licenses/LICENSE-2.0
%
% Unless required by applicable law or agreed to in writing, software
% distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
% WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
% License for the specific language governing permissions and limitations under
% the License.

-module(couch_mdns).
-include("../emdns/emdns.hrl").
-include("couch_db.hrl").

-behaviour(gen_server).

-export([start/0, init/1, handle_call/3, terminate/2]).
-export([handle_http_req/1]).

start() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

stop() ->
    gen_server:cast(?MODULE, stop).

new() ->
    gen_server:call(?MODULE, create).

init([]) ->
    BindAddress0 = couch_config:get("httpd", "bind_address", "0.0.0.0"),
    [Ip0, Ip1, Ip2, Ip3] = [list_to_integer(T) || T <- string:tokens(BindAddress0, ".")],
    BindAddress = {Ip0, Ip1, Ip2, Ip3},
    ?LOG_DEBUG("~p", [BindAddress0]),
    Port0 = couch_config:get("httpd", "port", "5984"),
    Port = list_to_integer(Port0),
    {_Socket, Pid} = emdns:start(),
    % Register ourselves as a service if [httpd] discoverable = true
    case couch_config:get("httpd", "discoverable", false) of
        "true" ->
            emdns:register_service(Pid, #service{
                name="CouchDB." ++ BindAddress0 ++ "-" ++ Port0 ++ "._http._tcp.local",
                type="_http._tcp.local",
                address=BindAddress,
                port=Port,
                server=BindAddress0
            });
        _ ->
            noop
    end,
    emdns:subscribe(Pid, "_http._tcp.local"),
    {ok, Pid}.

terminate(_Reason, _State) ->
    ok.

handle_call(getsubscriptions, _From, Pid) ->
    {reply, emdns:getsubscriptions(Pid), Pid}.

handle_http_req(#httpd{method='GET'}=Req) ->
    {ok, Subs} = gen_server:call(?MODULE, getsubscriptions, infinity),
    ?LOG_DEBUG("SUBSCRIPTIONS: ~p", [Subs]),
    List = case dict:find("_http._tcp.local", Subs) of
        {ok, Data} ->
            dict:fold(fun (Key, Value, AccIn) ->
                case Key of
                    "CouchDB." ++ _Rest ->
                        case Value of
                            #service{
                                server=Server,
                                address=Address,
                                port=Port
                            } when is_list(Server) -> [{[
                                    {server, ?l2b(Server)},
                                    {address, case Address of
                                        undefined -> null;
                                        _ -> ?l2b(string:join([integer_to_list(I) || I <- case is_binary(Address) of
                                            true -> ?b2l(Address);
                                            _ -> tuple_to_list(Address)
                                        end], "."))
                                    end},
                                    {port, Port}
                                ]} | AccIn];
                            _ -> AccIn
                        end;
                    _ ->
                        AccIn
                end
            end, [], Data);
        error ->
            []
    end,
    Servers = {[{<<"servers">>, List}]},
    couch_httpd:send_json(Req, Servers);
handle_http_req(Req) ->
    couch_httpd:send_method_not_allowed(Req, "GET,HEAD").
