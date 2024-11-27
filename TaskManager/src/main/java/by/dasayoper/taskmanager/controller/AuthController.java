package by.dasayoper.taskmanager.controller;

import by.dasayoper.taskmanager.dto.form.SignInForm;
import by.dasayoper.taskmanager.security.details.AccountUserDetails;
import by.dasayoper.taskmanager.security.utils.JwtUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "API для авторизации и обновления токенов")
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;

    @PostMapping("/auth/login")
    @Operation(
            summary = "Авторизация пользователя",
            description = "Позволяет авторизовать пользователя по email и паролю и получить пару токенов (access и refresh).",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    content = @Content(
                            schema = @Schema(implementation = SignInForm.class)
                    )
            ),
            responses = {
                    @ApiResponse(responseCode = "200", description = "Успешная авторизация",
                            content = @Content(mediaType = "application/json",
                                    examples = @ExampleObject(value = "{\"accessToken\": \"<JWT_ACCESS>\", \"refreshToken\": \"<JWT_REFRESH>\"}"))),
                    @ApiResponse(responseCode = "401", description = "Неверные данные для входа",
                            content = @Content(mediaType = "application/json",
                                    examples = @ExampleObject(value = "{\"error\": \"Неверные данные для входа\"}")))
            }
    )
    public ResponseEntity<?> login(@RequestBody SignInForm signInForm) {
        try {
            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(signInForm.getEmail(), signInForm.getPassword());
            Authentication authentication = authenticationManager.authenticate(authenticationToken);
            AccountUserDetails accountUserDetails = (AccountUserDetails) authentication.getPrincipal();
            String accessToken = jwtUtils.createAccessToken(accountUserDetails);
            String refreshToken = jwtUtils.createRefreshToken(accountUserDetails);
            return ResponseEntity.ok(Map.of(
                    "accessToken", accessToken,
                    "refreshToken", refreshToken
            ));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Неверные данные для входа"));
        }
    }

    @PostMapping("/auth/refresh")
    @Operation(
            summary = "Обновление access-токена",
            description = "Обновляет access-токен на основе валидного refresh-токена.",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    content = @Content(
                            schema = @Schema(example = "{\"refreshToken\": \"<JWT_REFRESH>\"}")
                    )
            ),
            responses = {
                    @ApiResponse(responseCode = "200", description = "Токен успешно обновлен",
                            content = @Content(mediaType = "application/json",
                                    examples = @ExampleObject(value = "{\"accessToken\": \"<NEW_JWT_ACCESS>\"}"))),
                    @ApiResponse(responseCode = "401", description = "Неверный или истекший refresh-токен",
                            content = @Content(mediaType = "application/json",
                                    examples = @ExampleObject(value = "{\"error\": \"Неверный или истекший refresh-токен\"}")))
            }
    )
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");

        if (refreshToken == null || !jwtUtils.validateToken(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Неверный или истекший refresh-токен"));
        }

        String newAccessToken = jwtUtils.createAccessTokenFromRefreshToken(refreshToken);
        return ResponseEntity.ok(Map.of("accessToken", newAccessToken));
    }
}
