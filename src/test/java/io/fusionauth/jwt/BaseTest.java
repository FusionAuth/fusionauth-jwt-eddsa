/*
 * Copyright (c) 2022-2023, FusionAuth, All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

package io.fusionauth.jwt;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import io.fusionauth.jwt.json.Mapper;
import org.testng.Assert;

/**
 * @author Daniel DeGroff
 */
public abstract class BaseTest {
  private static Map<String, Object> deepSort(Map<String, Object> response) {
    Map<String, Object> sorted = new TreeMap<>();
    response.forEach((key, value) -> {
      if (value instanceof Map) {
        sorted.put(key, deepSort((Map) value));
      } else if (value instanceof List) {
        sorted.put(key, deepSort((List) value));
      } else {
        sorted.put(key, value);
      }
    });

    return sorted;
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private static List<Object> deepSort(List<Object> list) {
    List<Object> sorted = new ArrayList<>();
    list.forEach(value -> {
      if (value instanceof Map) {
        sorted.add(deepSort((Map) value));
      } else if (value instanceof List) {
        sorted.add(deepSort((List) value));
      } else {
        sorted.add(value);
      }
    });

    sorted.sort(Comparator.comparing(value -> new String(Mapper.prettyPrint(value))));
    return sorted;
  }

  protected void assertJSONEquals(Object object, String jsonFile) throws IOException {
    Map<String, Object> actual = Mapper.deserialize(Mapper.serialize(object), Map.class);
    Map<String, Object> expected = Mapper.deserialize(Files.readAllBytes(Paths.get(jsonFile)), Map.class);

    actual = deepSort(actual);
    expected = deepSort(expected);

    if (!actual.equals(expected)) {
      String actualString = new String(Mapper.prettyPrint(actual));
      String expectedString = new String(Mapper.prettyPrint(expected));
      throw new AssertionError("The actual JSON doesn't match the expected JSON output. expected [" + expectedString + "] but found [" + actualString + "]");
    }
  }

  protected Path getPath(String fileName) {
    return Paths.get("src/test/resources/" + fileName);
  }

  protected String readFile(String fileName) {
    try {
      return new String(Files.readAllBytes(Paths.get("src/test/resources/" + fileName)));
    } catch (IOException e) {
      Assert.fail("Unexpected file I/O exception.", e);
      return null;
    }
  }
}
