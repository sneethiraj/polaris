/*
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
package org.apache.polaris.extension.auth.ranger.test;

import static io.restassured.RestAssured.given;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.http.ContentType;
import java.util.Properties;
import org.junit.jupiter.api.Test;

@QuarkusTest
@TestProfile(RangerTestProfiles.EmbeddedPolicyWithUserAttrib.class)
public class RangerABACWithUserAttrIT extends RangerIntegrationTestBase {

  @Test
  void getCatalogListsWithoutAuthorization() {
    Properties userattr = new Properties();
    userattr.put("region", "region1");
    String regionUserToken = getUserToken("region1user", userattr);
    given()
        .contentType(ContentType.JSON)
        .header("Authorization", "Bearer " + regionUserToken)
        .get("/api/management/v1/catalogs")
        .then()
        .statusCode(403);
  }

  @Test
  void getCatalogListsWithAuthorization() {
    Properties userattr = new Properties();
    userattr.put("region", "region2");
    String regionUserToken = getUserToken("region2user", userattr);
    given()
        .contentType(ContentType.JSON)
        .header("Authorization", "Bearer " + regionUserToken)
        .get("/api/management/v1/catalogs")
        .then()
        .statusCode(200);
  }
}
