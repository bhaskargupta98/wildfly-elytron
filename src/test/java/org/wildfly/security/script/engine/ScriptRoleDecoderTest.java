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

import javax.script.ScriptException;
import javax.script.ScriptEngineManager;
import javax.script.Invocable;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class ScriptEngine {

    static ScriptEngineManager manager = new ScriptEngineManager();
    static javax.script.ScriptEngine jsEngine = manager.getEngineByName("nashorn");
    static Invocable invocable = (Invocable) jsEngine;
    static Object result;
    static {
        try {
            result = jsEngine.eval(new FileReader("src//Name.js"));
        } catch (ScriptException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }
    
    private static Object returnSetFromMap (String keyRef, Map<String, Set<String>> roleSet) throws ScriptException, NoSuchMethodException {
        return invocable.invokeFunction("returnSet",keyRef,roleSet);
    }
    
    public static boolean TestRoleDecoder() throws Exception {
        Set<String> s1 = new HashSet<>();
        s1.add("chd");
        s1.add("ldh");
        Set<String> s2 = new HashSet<>();
        s2.add("bhaskar");
        s2.add("adi");
        Map<String, Set<String>> roleMap = new HashMap<>();
        roleMap.put("city",s1);
        roleMap.put("name",s2);
        Set<String> ans = (Set<String>) returnSetFromMap("name",roleMap);
        return ans == s2;
    }
}
