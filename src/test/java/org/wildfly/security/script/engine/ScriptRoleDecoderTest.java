/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2018 Red Hat, Inc., and individual contributors
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

import org.junit.jupiter.api.Test;
import org.wildfly.security.authz.AuthorizationIdentity;
import org.wildfly.security.authz.Attributes;
import org.wildfly.security.authz.MapAttributes;
import org.wildfly.security.authz.Roles;
import javax.script.ScriptException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class ScriptRoleDecoderTest {
    String pathToJSFile="src//TestJSFile.js";
    ScriptRoleDecoder obj1; //Using default method
    ScriptRoleDecoder obj2; //Using myMethod present in JavaScript file

    {
        try {
            obj1 = new ScriptRoleDecoder(pathToJSFile,null);
            obj2 = new ScriptRoleDecoder(pathToJSFile,"myFunction");
        } catch (ScriptException e) {
            e.printStackTrace();
        }
    }
    Set<String> ss = createSet("student","teacher","staff");
    Attributes att = new MapAttributes(createMap("department",ss));
    AuthorizationIdentity authId = AuthorizationIdentity.basicIdentity(att);
    @Test
    public void testDefaultMethod() throws ScriptException, NoSuchMethodException {
        obj1.roleMap.put("student",createSet("gate","class","room"));
        Roles checkRole = Roles.fromSet(createSet("gate","class","room"));
        Roles roleDefault = obj1.decodeRolesHelper(authId,obj1.roleMap);
        assertEquals(checkRole,roleDefault);
    }
    @Test
    public void testMyMethod() throws ScriptException, NoSuchMethodException {
        obj2.roleMap.put("student",createSet("gate","class","room"));
        Roles checkRole = Roles.fromSet(createSet("gate","class","room"));
        Roles roleDefault = obj2.decodeRolesHelper(authId,obj2.roleMap);
        assertEquals(checkRole,roleDefault);
    }
    private Set<String> createSet(String... values) {
        HashSet<String> set = new HashSet<>();
        for (String s : values) set.add(s);
        return set;
    }
    private HashMap<String,Set<String>> createMap(String key, Set<String> value){
        HashMap<String,Set<String>> hashmap = new HashMap<>();
        hashmap.put(key,value);
        return hashmap;
    }

}
