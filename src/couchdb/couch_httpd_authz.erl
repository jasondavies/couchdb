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

-module(couch_httpd_authz).
-include("couch_db.hrl").

-export([get_permissions/4,get_acl/0,get_permissions_for_acl/3]).

get_permissions(DbName, Roles, [Rule|Rules], DefaultPermissions) ->
    RuleDbName = proplists:get_value(<<"db">>, Rule),
    DbPrefixSize = size(RuleDbName) - 1,
    DbSuffixSize = size(DbName) - DbPrefixSize,
    DbMatch = case RuleDbName of
        <<DbPrefix:DbPrefixSize/binary, "*">> ->
            case DbName of
                <<DbPrefix:DbPrefixSize/binary, _Rest:DbSuffixSize/binary>> -> true;
                _ -> false
            end;
        DbName -> true;
        _ -> false
    end,
    RoleMatch = case proplists:get_value(<<"role">>, Rule) of
        <<"*">> -> true;
        RuleRole -> lists:member(RuleRole, Roles)
    end,
    if
        DbMatch andalso RoleMatch ->
            RuleAllow = proplists:get_value(<<"allow">>, Rule, []),
            RuleDeny = proplists:get_value(<<"deny">>, Rule, []),
            {RuleAllow, RuleDeny};
        true -> 
            get_permissions(DbName, Roles, Rules, DefaultPermissions)
    end;
get_permissions(_DbName, _Roles, [], DefaultPermissions) -> DefaultPermissions.

get_acl() ->
    UserDbName = ?l2b(couch_config:get("couch_httpd_auth", "authentication_db")),
    case couch_db:open(UserDbName, [{user_ctx, #user_ctx{roles=[<<"_admin">>]}}]) of
        {ok, UserDb} ->
            try
                case couch_db:open_doc(UserDb, <<"_local/_acl">>) of
                    {ok, #doc{body={Props}}} ->
                        [Rule || {Rule} <- proplists:get_value(<<"rules">>, Props)];
                    _ ->
                        []
                end
            after
                catch couch_db:close(UserDb)
            end;
        _ ->
            []
    end.

get_permissions_for_acl(DbName, Roles, ACL) ->
    DefaultPermissions = {[<<"*">>], []},
    case lists:member(<<"_admin">>, Roles) of
        true -> {[<<"*">>], []};
        _ when DbName =/= <<"users">> ->
            % By default we allow all
            case ACL of
                [] -> DefaultPermissions;
                Rules -> get_permissions(DbName, Roles, Rules, DefaultPermissions)
            end;
        _ ->
            DefaultPermissions
    end.
