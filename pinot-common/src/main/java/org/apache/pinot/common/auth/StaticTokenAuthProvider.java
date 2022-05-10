/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.pinot.common.auth;

import java.util.Collections;
import java.util.Map;
import javax.ws.rs.core.HttpHeaders;
import org.apache.pinot.spi.auth.AuthProvider;


public class StaticTokenAuthProvider implements AuthProvider {
  public static final String HEADER = "header";
  public static final String PREFIX = "prefix";
  public static final String TOKEN = "token";

  protected final String _header;
  protected final String _prefix;
  protected final String _token;

  public StaticTokenAuthProvider(String token) {
    _header = HttpHeaders.AUTHORIZATION;
    _prefix = "";
    _token = token;
  }

  public StaticTokenAuthProvider(AuthConfig authConfig) {
    _header = AuthProviderUtils.getOrDefault(authConfig, HEADER, HttpHeaders.AUTHORIZATION);
    _prefix = AuthProviderUtils.getOrDefault(authConfig, PREFIX, "Basic");
    _token = authConfig.getProperties().get(TOKEN).toString();
  }

  @Override
  public Map<String, Object> getRequestHeaders() {
    return Collections.singletonMap(_header, makeToken());
  }

  @Override
  public String getTaskToken() {
    return makeToken();
  }

  private String makeToken() {
    String token = _token;
    if (token.startsWith(_prefix)) {
      return token;
    }
    return _prefix + " " + _token;
  }
}
