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
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import javax.annotation.Nullable;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.Header;
import org.apache.http.message.BasicHeader;
import org.apache.pinot.spi.auth.AuthProvider;


/**
 * Utility class to wrap inference of optimal auth provider from component configs.
 */
public final class AuthProviderUtils {
  private AuthProviderUtils() {
    // left blank
  }

  /**
   * Infer optimal auth provider based on the availability of static token, if any.
   *
   * @param authToken static auth token
   * @return auth provider
   */
  public static AuthProvider inferProvider(String authToken) {
    return inferProvider(authToken, null);
  }

  /**
   * Infer optimal auth provider based on the availability of token and token url, if any.
   *
   * @param authToken static auth token
   * @param authTokenUrl dynamic token URL
   * @return auth provider
   */
  public static AuthProvider inferProvider(String authToken, String authTokenUrl) {
    if (StringUtils.isNotBlank(authTokenUrl)) {
      return new UrlAuthProvider(authTokenUrl);
    }
    if (StringUtils.isNotBlank(authToken)) {
      return new StaticTokenAuthProvider(authToken);
    }
    return new NullAuthProvider();
  }

  /**
   * Resolve auth token right now, e.g. for job specs.
   *
   * @param authToken static auth token
   * @param authTokenUrl dynamic token URL
   * @return resolved static token
   */
  public static String resolveToToken(String authToken, String authTokenUrl) {
    return resolveToToken(inferProvider(authToken, authTokenUrl));
  }

  /**
   * Resolve auth provider to token right now.
   *
   * @param authProvider
   * @return
   */
  public static String resolveToToken(AuthProvider authProvider) {
    if (authProvider == null) {
      return null;
    }
    return authProvider.getHttpHeaders().entrySet().stream().findFirst().map(Map.Entry::getValue)
        .filter(Objects::nonNull).map(Object::toString).orElse(null);
  }

  /**
   * Convenience helper to convert Map to list of Http Headers
   * @param headers header map
   * @return list of http headers
   */
  public static List<Header> toHeaders(@Nullable Map<String, Object> headers) {
    if (headers == null) {
      return Collections.emptyList();
    }
    return headers.entrySet().stream().filter(entry -> Objects.nonNull(entry.getValue()))
        .map(entry -> new BasicHeader(entry.getKey(), entry.getValue().toString())).collect(Collectors.toList());
  }

  /**
   * Convenience helper to convert an optional authProvider to a list of http headers
   * @param authProvider auth provider
   * @return list of http headers
   */
  public static List<Header> toHeaders(@Nullable AuthProvider authProvider) {
    if (authProvider == null) {
      return Collections.emptyList();
    }
    return toHeaders(authProvider.getHttpHeaders());
  }
}
