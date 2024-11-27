package by.dasayoper.taskmanager.controller;

import by.dasayoper.taskmanager.dto.AccountDto;
import by.dasayoper.taskmanager.dto.form.SignUpForm;
import by.dasayoper.taskmanager.service.SignUpService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Tag(name = "Registration", description = "API для регистрации")
public class SignUpController {
    private final SignUpService signUpService;

    private final Logger LOGGER = LoggerFactory.getLogger(this.getClass());

    @PostMapping("/sign-up")
    @Operation(
            summary = "Регистрация нового пользователя",
            description = "Позволяет зарегистрировать нового пользователя, предоставив его данные (имя, фамилию, email, пароль).",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Данные для регистрации нового пользователя",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = SignUpForm.class)
                    )
            ),
            responses = {
                    @ApiResponse(
                            responseCode = "201",
                            description = "Пользователь успешно зарегистрирован",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = AccountDto.class),
                                    examples = @ExampleObject(value = "{\"id\": \"<UUID>\", \"firstName\": \"John\", \"lastName\": \"Doe\", \"email\": \"john.doe@example.com\", \"role\": \"USER\"}")
                            )
                    ),
                    @ApiResponse(responseCode = "400", description = "Некорректные данные регистрации")
            }
    )
    public ResponseEntity<AccountDto> signUp(@RequestBody @Valid SignUpForm signUpForm) {
        LOGGER.info("Получен запрос POST на регистрацию нового пользователя. URL: /sign-up");
        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(signUpService.signUp(signUpForm));
    }

}
