package com.example.securityExam.standard;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

public class Ut {
    public static class json {
        private static final ObjectMapper objectMapper=new ObjectMapper();

        public static String toString(Object obj) {
            try {
                return objectMapper.writeValueAsString(obj);
            }
            catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
