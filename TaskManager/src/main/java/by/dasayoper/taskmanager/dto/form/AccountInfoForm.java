package by.dasayoper.taskmanager.dto.form;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Builder;
import lombok.Data;

/**
 * DTO объект, который используется для передачи информации о пользователе в процессе редактирования данных профиля.
 * Хранит данные об имени и фамилии пользователя, которые проходят валидацию.
 *
 * <p>
 * Содержит следующие поля:
 * <ul>
 *     <li>Имя пользователя {@link #firstName}, которое должно быть от 2 до 30 символов, начинаться с заглавной буквы и содержать только буквы.</li>
 *     <li>Фамилия пользователя {@link #lastName}, которая должна соответствовать тем же требованиям.</li>
 * </ul>
 * </p>
 */
@Data
@Builder
@Schema(description = "Форма для обновления информации об аккаунте")
public class AccountInfoForm {

    @NotNull(message = "Имя не может быть пустым")
    @Pattern(regexp = "^[A-ZА-Я][a-zа-я]{1,29}$", message = "Имя должно начинаться с заглавной буквы, содержать только буквы и иметь длину от 2 до 30 символов")
    @Schema(description = "Имя пользователя", example = "Иван")
    private String firstName;

    @NotNull(message = "Фамилия не может быть пустой")
    @Pattern(regexp = "^[A-ZА-Я][a-zа-я]{1,29}$", message = "Фамилия должна начинаться с заглавной буквы, содержать только буквы и иметь длину от 2 до 30 символов")
    @Schema(description = "Фамилия пользователя", example = "Петров")
    private String lastName;
}
