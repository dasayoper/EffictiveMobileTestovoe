package by.dasayoper.taskmanager.dto.form;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Builder;
import lombok.Data;

/**
 * DTO объект, который используется для регистрации нового пользователя.
 * Содержит информацию, необходимую для создания нового аккаунта.
 * <p>
 * Включает следующие поля:
 * <ul>
 *     <li>Имя пользователя {@link #firstName}, которое должно быть длиной от 2 до 30 символов, начинаться с заглавной буквы и содержать только буквы.</li>
 *     <li>Фамилия пользователя {@link #lastName}, которая также должна быть длиной от 2 до 30 символов, начинаться с заглавной буквы и содержать только буквы.</li>
 *     <li>Email {@link #email}, который должен быть уникальным и соответствовать формату email.</li>
 *     <li>Пароль {@link #password}, который должен быть не короче 8 символов, содержать хотя бы одну цифру и один специальный символ.</li>
 * </ul>
 * </p>
 */
@Data
@Builder
@Schema(description = "Данные для регистрации нового пользователя")
public class SignUpForm {

    @NotNull(message = "Имя не может быть пустым")
    @Pattern(regexp = "^[A-ZА-Я][a-zа-я]{1,29}$", message = "Имя должно начинаться с заглавной буквы, содержать только буквы и иметь длину от 2 до 30 символов")
    @Schema(description = "Имя пользователя", example = "Иван")
    private String firstName;

    @NotNull(message = "Фамилия не может быть пустой")
    @Pattern(regexp = "^[A-ZА-Я][a-zа-я]{1,29}$", message = "Фамилия должна начинаться с заглавной буквы, содержать только буквы и иметь длину от 2 до 30 символов")
    @Schema(description = "Фамилия пользователя", example = "Петров")
    private String lastName;

    @NotNull(message = "Email не может быть пустым")
    @Email(message = "Указан некорректный формат email")
    @Schema(description = "Email пользователя", example = "ivan.petrov@example.com")
    private String email;

    @NotNull(message = "Пароль не может быть пустым")
    @Pattern(regexp = "^(?=.*\\d)(?=.*[_@$!%*?&])[A-Za-z\\d_@$!%*?&]{8,}$",
            message = "Пароль не может быть короче 8 символов и должен содержать хотя бы одну цифру и один специальный символ")
    @Schema(description = "Пароль пользователя", example = "password123!")
    private String password;
}
