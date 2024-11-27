package by.dasayoper.taskmanager.dto.form;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Data;

/**
 * DTO объект, который используется для авторизации пользователя.
 * Содержит информацию, необходимую для авторизации в системе.
 * <p>
 * Включает следующие поля:
 * <ul>
 *     <li>Email {@link #email}, который должен быть уникальным и соответствовать формату email.</li>
 *     <li>Пароль {@link #password}, который должен быть не короче 8 символов, содержать хотя бы одну цифру и один специальный символ.</li>
 * </ul>
 * </p>
 */
@Data
@Builder
@Schema(description = "Форма для авторизации пользователя")
public class SignInForm {

    @NotNull(message = "Email не может быть пустым")
    @Email(message = "Указан некорректный формат email")
    @Schema(description = "Email пользователя", example = "user@example.com")
    private String email;

    @NotNull(message = "Пароль не может быть пустым")
    @Schema(description = "Пароль пользователя", example = "password123!")
    private String password;
}

