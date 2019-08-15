/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2019 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wildfly.security.script.engine;
import main.java.RoleDecoder;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.Roles;
import javax.script.Invocable;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;
import java.util.Map;
import java.util.Set;

public class ScriptRoleDecoder implements RoleDecoder {
    private ScriptEngineManager manager;
    private javax.script.ScriptEngine jsEngine;
    private Invocable invocable;
    private String pathToJSFile;
    private String jsFunction;
    public ScriptRoleDecoder(){
        manager  = new ScriptEngineManager();
        jsEngine = manager.getEngineByName("nashorn");
        invocable = (Invocable) jsEngine;
    }
    public void initialize(Map<String, String> configuration) throws ScriptException {
        for(Map.Entry<String,String> entrySet : configuration.entrySet()){
            pathToJSFile = entrySet.getKey();
            jsEngine.eval(pathToJSFile);
            jsFunction = entrySet.getValue();

        }

    }
    public Roles decodeRoles(AuthorizationIdentity authorizationIdentity){ //returns Roles object

        try {
            return decodeRolesHelper(authorizationIdentity);
        } catch (ScriptException e) {
            throw new RuntimeException();
        } catch (NoSuchMethodException e) {
            throw new RuntimeException();
        }


    }
    private Roles decodeRolesHelper(AuthorizationIdentity authorizationIdentity) throws ScriptException, NoSuchMethodException { //helper function to use custom method written in JS
        String attributeKey = authorizationIdentity.getAttributes().getFirst("department"); //key attribute corresponding to the desired attribute kind
        Set<String> setOfStrings =  (Set<String>) invocable.invokeFunction((jsFunction!=null) ? jsFunction : "returnSetOfRoles",attributeKey); ////By default JS Function "returnSetOfRoles" will be used unless passed in while object creation
        Roles decodedRoleSet = Roles.fromSet(setOfStrings);
        return decodedRoleSet;
    }
}




