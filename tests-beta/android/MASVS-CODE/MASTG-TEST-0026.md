---
title: Use of Object Persistence using JSON
platform: android
id: MASTG-TEST-0266
type: [static]
weakness: MASWE-0088
---

## Overview

Android provides the JSONObject and JSONArray classes, which are essential for handling JSON data. JSON or JavaScript Object Notation, is a lightweight format for data interchange that is both human-readable and easy for machines to parse and generate. One important characteristic of JSON representations is that they are based on strings, making them immutable. This immutability means that once a JSON object is created, it cannot be changed. As a result, if sensitive information is stored within a JSON structure, it becomes more difficult to completely remove that information from memory, posing potential security risks. Additionally, JSON data can be stored in various locations, including NoSQL databases, which are designed to handle unstructured data, or in files on a local or remote file system, providing flexibility in how data is managed and accessed.

## Steps

1. Run a static analysis tool such as @MASTG-TOOL-0110 on the code and look for uses of the `JSONObject` and `JSONArray`.

## Observation

The output file shows usages of the object persistance using `JSONObject` and `JSONArray` in the code.

## Evaluation

The test fails if `org.json.JSONObject` and `org.json.JSONArray` was found in the code.
