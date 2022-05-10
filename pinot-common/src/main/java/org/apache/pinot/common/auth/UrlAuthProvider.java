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

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;
import javax.ws.rs.core.HttpHeaders;
import org.apache.commons.io.IOUtils;
import org.apache.pinot.spi.auth.AuthProvider;


public class UrlAuthProvider implements AuthProvider {
  final String _header;
  final String _prefix;
  final URL _url;

  public UrlAuthProvider(String url) {
    try {
      _header = HttpHeaders.AUTHORIZATION;
      _prefix = "Bearer ";
      _url = new URL(url);
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException(e);
    }
  }

  public UrlAuthProvider(String header, String prefix, String url) {
    try {
      _header = header;
      _prefix = prefix;
      _url = new URL(url);
    } catch (MalformedURLException e) {
      throw new IllegalArgumentException(e);
    }
  }

  @Override
  public Map<String, Object> getHttpHeaders() {
    try {
      return Collections.singletonMap(_header, _prefix + IOUtils.toString(_url, StandardCharsets.UTF_8));
    } catch (IOException e) {
      throw new IllegalArgumentException("Could not access auth url", e);
    }
  }
}
