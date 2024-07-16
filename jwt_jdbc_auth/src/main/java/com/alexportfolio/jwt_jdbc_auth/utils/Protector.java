package com.alexportfolio.jwt_jdbc_auth.utils;

import java.util.HashMap;

// protection from brute force
// isAllowed() returns true only if withing the TIMEOUT time complain() was called less than the LIMIT times
public class Protector{
    private static class LoginAttempts{
        private int counter;
        private long lastTime = System.currentTimeMillis();;
    }

    static final private int TIMEOUT = 5 * 60 * 1000;
    static final private int LIMIT = 3;

    static private HashMap<String, LoginAttempts> registry = new HashMap<>();

    public static void complain(String username){
        var attempts = registry.get(username);
        attempts.counter++;
        attempts.lastTime = System.currentTimeMillis();
        registry.put(username, attempts);
    }

    public static boolean isAllowed(String username){
        var attempt = registry.getOrDefault(username, new LoginAttempts());
        if(System.currentTimeMillis()< attempt.lastTime + TIMEOUT) {
            if (attempt.counter < LIMIT) {
                registry.put(username, attempt);
                return true;
            } else {
                complain(username);
            }
        } else {
            attempt.counter = 1;
            attempt.lastTime = System.currentTimeMillis();
            registry.put(username, attempt);
            return true;
        }
        return false;
    }
}
