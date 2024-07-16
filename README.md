jwt_jdbc_auth
Working block of Spring Boot Security + Web + JDBC. Uses JWT Tokens and Basic way of protecting endpoints.
Has Protection against password brute force. Utilizes JdbcUserDetailsManager for authorization and authentication.
The project's logic:
1. Regular authentication project with JdbcUserDetailsManager (needs standard SQL tables: "users" with username/password/enabled columns and "authorities" with username/authority
2. JWTAuthFilter in the Security Filter Chain:
    • Checks if token is present. If present, extracts information from it (username, roles)
    • If token is invalid or expired, the exception will be thrown, but we can not handle it manually. Handling is performed by 
 .exceptionHandling() method in the SecurityFilterChain
    • If token decoded successfully, creates Authentication object and add it to the Security Context using information from the token.
   We don't need to hit the DB to check user authorities on each request. If token expired/modified exception is thrown automatically.
4. TokenProcessor handles all logic related to the JWT token coding/decoding
5. JWTAuthController has 2 endpoints:
    • /auth accepts username/password in json, validates it and returns token on success
    • /reg has POST/PATCH/DELETE methods for user creation, password change and deletion. By default user admin can not be deleted.
    • Protector class count unsuccessful login attempts and "locks" the user for specified timeout.
