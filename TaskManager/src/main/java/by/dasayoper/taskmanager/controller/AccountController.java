package by.dasayoper.taskmanager.controller;

import by.dasayoper.taskmanager.dto.AccountDto;
import by.dasayoper.taskmanager.dto.form.AccountInfoForm;
import by.dasayoper.taskmanager.dto.page.AccountPage;
import by.dasayoper.taskmanager.dto.util.AccountFilterParameters;
import by.dasayoper.taskmanager.service.AccountService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
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
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequiredArgsConstructor
@Tag(name = "Accounts", description = "API для работы с аккаунтами пользователей")
public class AccountController {
    private final AccountService accountService;

    private final Logger LOGGER = LoggerFactory.getLogger(this.getClass());

    @GetMapping("/accounts/{id}")
    @PreAuthorize("hasAuthority('ADMIN')")
    @Operation(
            summary = "Получение аккаунта по ID",
            description = "Возвращает информацию об аккаунте по его уникальному ID.",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Успешный ответ",
                            content = @Content(mediaType = "application/json",
                                    schema = @Schema(implementation = AccountDto.class))),
                    @ApiResponse(responseCode = "404", description = "Аккаунт не найден")
            }
    )
    public ResponseEntity<AccountDto> getAccount(@PathVariable("id") UUID id) {
        LOGGER.info("Получен запрос GET на получение аккаунта с id: {}", id);
        return ResponseEntity.ok()
                .body(accountService.getById(id));
    }

    @GetMapping("/accounts")
    @PreAuthorize("hasAuthority('ADMIN')")
    @Operation(
            summary = "Получение списка аккаунтов с фильтрами",
            description = "Возвращает список аккаунтов с возможностью фильтрации по следующим параметрам:\n" +
                    "1. Имя пользователя (firstName)\n" +
                    "2. Фамилия пользователя (lastName)\n" +
                    "3. Email пользователя (email)\n" +
                    "4. Наличие назначенных задач (hasAssignedTasks)\n" +
                    "5. Номер страницы (page)\n" +
                    "6. Размер страницы (size)",
            parameters = {
                    @Parameter(name = "firstName", description = "Имя пользователя для фильтрации", examples = @ExampleObject(value = "Иван")),
                    @Parameter(name = "lastName", description = "Фамилия пользователя для фильтрации", examples = @ExampleObject(value = "Петров")),
                    @Parameter(name = "email", description = "Email пользователя для фильтрации", examples = @ExampleObject(value = "ivan.petrov@example.com")),
                    @Parameter(name = "hasAssignedTasks", description = "Наличие назначенных задач для фильтрации, принимает значение true или false", examples = @ExampleObject(value = "true")),
                    @Parameter(name = "page", description = "Номер страницы для пагинации, начинается с 0", examples = @ExampleObject(value = "0")),
                    @Parameter(name = "size", description = "Размер страницы для пагинации", examples = @ExampleObject(value = "10"))
            },

            responses = {
                    @ApiResponse(responseCode = "200", description = "Успешный ответ",
                            content = @Content(mediaType = "application/json",
                                    schema = @Schema(implementation = AccountPage.class))),
                    @ApiResponse(responseCode = "400", description = "Некорректные параметры запроса")
            }
    )
    public ResponseEntity<AccountPage> getAllAccounts(@RequestParam(required = false) String firstName,
                                                      @RequestParam(required = false) String lastName,
                                                      @RequestParam(required = false) String email,
                                                      @RequestParam(required = false) String hasAssignedTasks,
                                                      @RequestParam(defaultValue = "0") int page,
                                                      @RequestParam(defaultValue = "10") int size) {
        LOGGER.info("Получен запрос GET на получение списка аккаунтов. Параметры: firstName={}, lastName={}, email={}, hasAssignedTasks={}, page={}, size={}",
                firstName, lastName, email, hasAssignedTasks, page, size);

        AccountFilterParameters filterParameters = AccountFilterParameters.buildAccountFilterParameters(firstName, lastName, email, hasAssignedTasks, page, size);

        AccountPage accountPage = accountService.getAllFiltered(filterParameters);

        return ResponseEntity.ok()
                .body(accountPage);
    }

    @PatchMapping("/accounts/{id}")
    @PreAuthorize("hasAnyAuthority('ADMIN','COMMON_USER')")
    @Operation(
            summary = "Обновление информации об аккаунте",
            description = "Обновляет информацию об аккаунте по его ID.",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Данные для обновления профиля пользователя",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = AccountInfoForm.class)
                    )
            ),
            responses = {
                    @ApiResponse(responseCode = "202", description = "Аккаунт успешно обновлен",
                            content = @Content(mediaType = "application/json",
                                    schema = @Schema(implementation = AccountDto.class))),
                    @ApiResponse(responseCode = "400", description = "Некорректные данные для обновления"),
                    @ApiResponse(responseCode = "404", description = "Аккаунт не найден")
            }
    )
    public ResponseEntity<AccountDto> updateAccount(@PathVariable("id") UUID id,
                                                    @RequestBody @Valid AccountInfoForm form) {
        LOGGER.info("Получен запрос PATCH на обновление аккаунта с id: {}", id);
        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(accountService.updateById(id, form));
    }
}
