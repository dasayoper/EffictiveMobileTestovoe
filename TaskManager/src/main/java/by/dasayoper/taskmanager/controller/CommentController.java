package by.dasayoper.taskmanager.controller;

import by.dasayoper.taskmanager.dto.CommentDto;
import by.dasayoper.taskmanager.dto.form.CommentForm;
import by.dasayoper.taskmanager.dto.page.CommentPage;
import by.dasayoper.taskmanager.dto.util.CommentFilterParameters;
import by.dasayoper.taskmanager.service.CommentService;
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
@Tag(name = "Comments", description = "API для работы с комментариями")
public class CommentController {
    private final CommentService commentService;

    private final Logger LOGGER = LoggerFactory.getLogger(this.getClass());

    @GetMapping("/comments/{id}")
    @PreAuthorize("hasAnyAuthority('ADMIN','COMMON_USER')")
    @Operation(
            summary = "Получение комментария по ID",
            description = "Возвращает комментарий по его уникальному ID.",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Успешный ответ",
                            content = @Content(mediaType = "application/json",
                                    schema = @Schema(implementation = CommentDto.class))),
                    @ApiResponse(responseCode = "404", description = "Комментарий не найден")
            }
    )
    public ResponseEntity<CommentDto> getComment(@PathVariable("id") UUID id) {
        LOGGER.info("Получен запрос GET на получение комментария. URL: /comments/{}", id);
        return ResponseEntity.ok()
                .body(commentService.getById(id));
    }

    @GetMapping("/comments")
    @PreAuthorize("hasAnyAuthority('ADMIN','COMMON_USER')")
    @Operation(
            summary = "Получение всех комментариев с фильтрами",
            description = "Возвращает список комментариев с возможностью фильтрации по следующим параметрам:\n" +
                    "1. Текст комментария (text)\n" +
                    "2. ID автора комментария (authorId)\n" +
                    "3. ID задачи, к которой относится комментарий (taskId)\n" +
                    "4. Дата начала фильтрации (startDate)\n" +
                    "5. Дата окончания фильтрации (endDate)\n" +
                    "6. Флаг редактирования комментария (wasEdited)\n" +
                    "7. Минимальная длина комментария (minLength)\n" +
                    "8. Максимальная длина комментария (maxLength)\n" +
                    "9. Номер страницы (page) для пагинации\n" +
                    "10. Размер страницы (size) для пагинации",
            parameters = {
                    @Parameter(name = "text", description = "Текст комментария, который может быть использован для фильтрации", examples = @ExampleObject(value = "Ошибка в коде")),
                    @Parameter(name = "authorId", description = "ID автора комментария для фильтрации", examples = @ExampleObject(value = "<UUID>")),
                    @Parameter(name = "taskId", description = "ID задачи, к которой относится комментарий", examples = @ExampleObject(value = "<UUID>")),
                    @Parameter(name = "startDate", description = "Дата начала периода для фильтрации комментариев (формат: yyyy-MM-dd)", examples = @ExampleObject(value = "2024-01-01")),
                    @Parameter(name = "endDate", description = "Дата окончания периода для фильтрации комментариев (формат: yyyy-MM-dd)", examples = @ExampleObject(value = "2024-12-31")),
                    @Parameter(name = "wasEdited", description = "Флаг редактирования комментария, если true, то комментарий был отредактирован", examples = @ExampleObject(value = "true")),
                    @Parameter(name = "minLength", description = "Минимальная длина комментария для фильтрации", examples = @ExampleObject(value = "10")),
                    @Parameter(name = "maxLength", description = "Максимальная длина комментария для фильтрации", examples = @ExampleObject(value = "500")),
                    @Parameter(name = "page", description = "Номер страницы для пагинации", examples = @ExampleObject(value = "0")),
                    @Parameter(name = "size", description = "Размер страницы для пагинации", examples = @ExampleObject(value = "10"))
            },
            responses = {
                    @ApiResponse(responseCode = "200", description = "Успешный ответ",
                            content = @Content(mediaType = "application/json",
                                    schema = @Schema(implementation = CommentPage.class))),
                    @ApiResponse(responseCode = "400", description = "Некорректные параметры запроса")
            }
    )
    public ResponseEntity<CommentPage> getAllComments(@RequestParam(required = false) String text,
                                                      @RequestParam(required = false) String authorId,
                                                      @RequestParam(required = false) String taskId,
                                                      @RequestParam(required = false) String startDate,
                                                      @RequestParam(required = false) String endDate,
                                                      @RequestParam(required = false) String wasEdited,
                                                      @RequestParam(required = false) String minLength,
                                                      @RequestParam(required = false) String maxLength,
                                                      @RequestParam(defaultValue = "0") int page,
                                                      @RequestParam(defaultValue = "10") int size) {
        LOGGER.info("Получен запрос GET на получение всех комментариев. URL: /comments, параметры: text={}, authorId={}, taskId={}, startDate={}, endDate={}, wasEdited={}, minLength={}, maxLength={}, page={}, size={}",
                text, authorId, taskId, startDate, endDate, wasEdited, minLength, maxLength, page, size);

        CommentFilterParameters filterParameters = CommentFilterParameters.createCommentFilterParameters(text, authorId, taskId, startDate, endDate, wasEdited, minLength, maxLength, page, size);
        CommentPage commentPage = commentService.getAllFiltered(filterParameters);

        return ResponseEntity.ok()
                .body(commentPage);
    }

    @PostMapping("/tasks/{id}/comments")
    @PreAuthorize("hasAnyAuthority('ADMIN','COMMON_USER')")
    @Operation(
            summary = "Добавление комментария",
            description = "Добавляет новый комментарий для указанной задачи.",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Данные комментария для добавления",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = CommentForm.class)
                    )
            ),
            responses = {
                    @ApiResponse(responseCode = "201", description = "Комментарий успешно создан",
                            content = @Content(mediaType = "application/json",
                                    schema = @Schema(implementation = CommentDto.class))),
                    @ApiResponse(responseCode = "400", description = "Некорректные данные для комментария"),
                    @ApiResponse(responseCode = "404", description = "Задача не найдена")
            }
    )
    public ResponseEntity<CommentDto> addComment(@PathVariable("id") UUID id,
                                                 @RequestBody @Valid CommentForm form) {
        LOGGER.info("Получен запрос POST на добавление комментария. URL: /tasks/{}/comments, тело запроса: {}", id, form);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(commentService.save(id, form));
    }

    @PatchMapping("/comments/{id}")
    @PreAuthorize("hasAnyAuthority('ADMIN','COMMON_USER')")
    @Operation(
            summary = "Обновление комментария",
            description = "Обновляет информацию о комментарии по его ID.",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Данные для обновления комментария",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = CommentForm.class)
                    )
            ),
            responses = {
                    @ApiResponse(responseCode = "202", description = "Комментарий успешно обновлен",
                            content = @Content(mediaType = "application/json",
                                    schema = @Schema(implementation = CommentDto.class))),
                    @ApiResponse(responseCode = "404", description = "Комментарий не найден")
            }
    )
    public ResponseEntity<CommentDto> updateComment(@PathVariable("id") UUID id,
                                                    @RequestBody @Valid CommentForm form) {
        LOGGER.info("Получен запрос PATCH на обновление комментария. URL: /comments/{}, тело запроса: {}", id, form);
        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(commentService.updateById(id, form));
    }

    @DeleteMapping("/comments/{id}")
    @PreAuthorize("hasAnyAuthority('ADMIN','COMMON_USER')")
    @Operation(
            summary = "Удаление комментария",
            description = "Удаляет комментарий по его ID.",
            responses = {
                    @ApiResponse(responseCode = "202", description = "Комментарий успешно удален"),
                    @ApiResponse(responseCode = "404", description = "Комментарий не найден")
            }
    )
    public ResponseEntity<?> deleteComment(@PathVariable("id") UUID id) {
        LOGGER.info("Получен запрос DELETE на удаление комментария. URL: /comments/{}", id);
        commentService.deleteById(id);
        return ResponseEntity.status(HttpStatus.ACCEPTED).build();
    }

    @GetMapping("/tasks/{id}/comments")
    @PreAuthorize("hasAnyAuthority('ADMIN','COMMON_USER')")
    @Operation(
            summary = "Получение комментариев для конкретной задачи",
            description = "Возвращает список комментариев для указанной задачи с возможностью фильтрации по следующим параметрам:\n" +
                    "1. Текст комментария (text)\n" +
                    "2. ID автора комментария (authorId)\n" +
                    "3. Дата начала фильтрации (startDate)\n" +
                    "4. Дата окончания фильтрации (endDate)\n" +
                    "5. Флаг редактирования комментария (wasEdited)\n" +
                    "6. Минимальная длина комментария (minLength)\n" +
                    "7. Максимальная длина комментария (maxLength)\n" +
                    "8. Номер страницы (page) для пагинации\n" +
                    "9. Размер страницы (size) для пагинации",
            parameters = {
                    @Parameter(name = "text", description = "Текст комментария, который может быть использован для фильтрации", examples = @ExampleObject(value = "Ошибка в коде")),
                    @Parameter(name = "authorId", description = "ID автора комментария для фильтрации", examples = @ExampleObject(value = "<UUID>")),
                    @Parameter(name = "startDate", description = "Дата начала периода для фильтрации комментариев (формат: yyyy-MM-dd)", examples = @ExampleObject(value = "2024-01-01")),
                    @Parameter(name = "endDate", description = "Дата окончания периода для фильтрации комментариев (формат: yyyy-MM-dd)", examples = @ExampleObject(value = "2024-12-31")),
                    @Parameter(name = "wasEdited", description = "Флаг редактирования комментария, если true, то комментарий был отредактирован", examples = @ExampleObject(value = "true")),
                    @Parameter(name = "minLength", description = "Минимальная длина комментария для фильтрации", examples = @ExampleObject(value = "10")),
                    @Parameter(name = "maxLength", description = "Максимальная длина комментария для фильтрации", examples = @ExampleObject(value = "500")),
                    @Parameter(name = "page", description = "Номер страницы для пагинации", examples = @ExampleObject(value = "0")),
                    @Parameter(name = "size", description = "Размер страницы для пагинации", examples = @ExampleObject(value = "10"))
            },
            responses = {
                    @ApiResponse(responseCode = "200", description = "Успешный ответ",
                            content = @Content(mediaType = "application/json",
                                    schema = @Schema(implementation = CommentPage.class))),
                    @ApiResponse(responseCode = "400", description = "Некорректные параметры запроса")
            }
    )
    public ResponseEntity<CommentPage> getAllTaskComments(@PathVariable("id") UUID id,
                                                          @RequestParam(required = false) String text,
                                                          @RequestParam(required = false) String authorId,
                                                          @RequestParam(required = false) String startDate,
                                                          @RequestParam(required = false) String endDate,
                                                          @RequestParam(required = false) String wasEdited,
                                                          @RequestParam(required = false) String minLength,
                                                          @RequestParam(required = false) String maxLength,
                                                          @RequestParam(defaultValue = "0") int page,
                                                          @RequestParam(defaultValue = "10") int size) {
        LOGGER.info("Получен запрос GET на получение комментариев задачи. URL: /tasks/{}/comments, параметры: text={}, authorId={}, startDate={}, endDate={}, wasEdited={}, minLength={}, maxLength={}, page={}, size={}",
                id, text, authorId, startDate, endDate, wasEdited, minLength, maxLength, page, size);

        CommentFilterParameters commentFilterParameters = CommentFilterParameters.createCommentFilterParameters(text, authorId, String.valueOf(id), startDate, endDate, wasEdited, minLength, maxLength, page, size);
        CommentPage commentPage = commentService.getAllFiltered(commentFilterParameters);

        return ResponseEntity.ok()
                .body(commentPage);
    }

    @GetMapping("/accounts/{id}/comments")
    @PreAuthorize("hasAnyAuthority('ADMIN','COMMON_USER')")
    @Operation(
            summary = "Получение комментариев конкретного автора",
            description = "Возвращает список комментариев, написанных указанным автором с возможностью фильтрации по следующим параметрам:\n" +
                    "1. Текст комментария (text)\n" +
                    "2. ID задачи, к которой относится комментарий (taskId)\n" +
                    "3. Дата начала фильтрации (startDate)\n" +
                    "4. Дата окончания фильтрации (endDate)\n" +
                    "5. Флаг редактирования комментария (wasEdited)\n" +
                    "6. Минимальная длина комментария (minLength)\n" +
                    "7. Максимальная длина комментария (maxLength)\n" +
                    "8. Номер страницы (page) для пагинации\n" +
                    "9. Размер страницы (size) для пагинации",
            parameters = {
                    @Parameter(name = "text", description = "Текст комментария, который может быть использован для фильтрации", examples = @ExampleObject(value = "Ошибка в коде")),
                    @Parameter(name = "taskId", description = "ID задачи, к которой относится комментарий", examples = @ExampleObject(value = "<UUID>")),
                    @Parameter(name = "startDate", description = "Дата начала периода для фильтрации комментариев (формат: yyyy-MM-dd)", examples = @ExampleObject(value = "2024-01-01")),
                    @Parameter(name = "endDate", description = "Дата окончания периода для фильтрации комментариев (формат: yyyy-MM-dd)", examples = @ExampleObject(value = "2024-12-31")),
                    @Parameter(name = "wasEdited", description = "Флаг редактирования комментария, если true, то комментарий был отредактирован", examples = @ExampleObject(value = "true")),
                    @Parameter(name = "minLength", description = "Минимальная длина комментария для фильтрации", examples = @ExampleObject(value = "10")),
                    @Parameter(name = "maxLength", description = "Максимальная длина комментария для фильтрации", examples = @ExampleObject(value = "500")),
                    @Parameter(name = "page", description = "Номер страницы для пагинации", examples = @ExampleObject(value = "0")),
                    @Parameter(name = "size", description = "Размер страницы для пагинации", examples = @ExampleObject(value = "10"))
            },
            responses = {
                    @ApiResponse(responseCode = "200", description = "Успешный ответ",
                            content = @Content(mediaType = "application/json",
                                    schema = @Schema(implementation = CommentPage.class))),
                    @ApiResponse(responseCode = "400", description = "Некорректные параметры запроса")
            }
    )
    public ResponseEntity<CommentPage> getAllAccountComments(@PathVariable("id") UUID id,
                                                             @RequestParam(required = false) String text,
                                                             @RequestParam(required = false) String taskId,
                                                             @RequestParam(required = false) String startDate,
                                                             @RequestParam(required = false) String endDate,
                                                             @RequestParam(required = false) String wasEdited,
                                                             @RequestParam(required = false) String minLength,
                                                             @RequestParam(required = false) String maxLength,
                                                             @RequestParam(defaultValue = "0") int page,
                                                             @RequestParam(defaultValue = "10") int size) {
        LOGGER.info("Получен запрос GET на получение комментариев аккаунта. URL: /accounts/{}/comments, параметры: text={}, taskId={}, startDate={}, endDate={}, wasEdited={}, minLength={}, maxLength={}, page={}, size={}",
                id, text, taskId, startDate, endDate, wasEdited, minLength, maxLength, page, size);

        CommentFilterParameters commentFilterParameters = CommentFilterParameters.createCommentFilterParameters(text, String.valueOf(id), taskId, startDate, endDate, wasEdited, minLength, maxLength, page, size);
        CommentPage commentPage = commentService.getAllFiltered(commentFilterParameters);

        return ResponseEntity.ok()
                .body(commentPage);
    }
}
