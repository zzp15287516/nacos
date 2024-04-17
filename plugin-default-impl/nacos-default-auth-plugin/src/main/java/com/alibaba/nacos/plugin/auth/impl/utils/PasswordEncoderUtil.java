/*
 * Copyright 1999-2021 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.nacos.plugin.auth.impl.utils;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.regex.Pattern;

/**
 * Password encoder tool.
 *
 * @author nacos
 */
public class PasswordEncoderUtil {

    public static Boolean matches(String raw, String encoded) {
        return new BCryptPasswordEncoder().matches(raw, encoded);
    }

    public static String encode(String raw) {
        return new BCryptPasswordEncoder().encode(raw);
    }

    public static Boolean simpleCheck(String raw) {
        String reg = "^(?![a-zA-Z]+$)(?![A-Z0-9]+$)(?![A-Z\\W-~#?!@$%^*&]+$)(?![a-z0-9]+$)(?![a-z\\W-~#?!@$%^*&]+$)(?![0-9\\W-~#?!@$%^*&]+$)[a-zA-Z0-9\\W-~#?!@$%^*&]{8,}$";
        return Pattern.compile(reg).matcher(raw).matches();
    }
}
