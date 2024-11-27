package by.dasayoper.taskmanager.controller;

import by.dasayoper.taskmanager.dto.TaskDto;
import by.dasayoper.taskmanager.dto.form.TaskForm;
import by.dasayoper.taskmanager.dto.form.TaskStatusForm;
import by.dasayoper.taskmanager.dto.page.TaskPage;
import by.dasayoper.taskmanager.dto.util.TaskFilterParameters;
import by.dasayoper.taskmanager.service.TaskService;
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
@Tag(name = "Tasks", description = "API для работы с задачами")
public class TaskController {
    private final TaskService taskService;

    private final Logger LOGGER = LoggerFactory.getLogger(this.getClass());

    @GetMapping("/tasks/{id}")
    @PreAuthorize("hasAnyAuthority('ADMIN','COMMON_USER')")
    @Operation(
            summary = "Получение задачи по ID",
            description = "Возвращает информацию о задаче по ее уникальному ID.",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Успешный ответ",
                            content = @Content(mediaType = "application/json",
                                    schema = @Schema(implementation = TaskDto.class))),
                    @ApiResponse(responseCode = "404", description = "Задача не найдена")
            }
    )
    public ResponseEntity<TaskDto> getTask(@PathVariable("id") UUID id) {
        LOGGER.info("Получен запрос GET на получение задачи. URL: /tasks/{}", id);
        return ResponseEntity.ok()
                .body(taskService.getById(id));
    }

    @GetMapping("/tasks")
    @PreAuthorize("hasAnyAuthority('ADMIN','COMMON_USER')")
    @Operation(
            summary = "Получение списка задач",
            description = "Возвращает список всех задач с возможностью фильтрации по следующим параметрам:\n" +
                    "1. Заголовок задачи (title)\n" +
                    "2. Описание задачи (description)\n" +
                    "3. Статус задачи (status)\n" +
                    "4. Приоритет задачи (priority)\n" +
                    "5. Идентификатор автора задачи (authorId)\n" +
                    "6. Идентификатор исполнителя задачи (executorId)\n" +
                    "7. Номер страницы (page)\n" +
                    "8. Размер страницы (size)",
            parameters = {
                    @Parameter(name = "title", description = "Заголовок задачи для фильтрации", examples = @ExampleObject(value = "Рефакторинг")),
                    @Parameter(name = "description", description = "Описание задачи для фильтрации", examples = @ExampleObject(value = "Изменить код класса UserServiceImpl")),
                    @Parameter(name = "status", description = "Статус задачи для фильтрации", examples = @ExampleObject(value = "REVIEW")),
                    @Parameter(name = "priority", description = "Приоритет задачи для фильтрации", examples = @ExampleObject(value = "LOW")),
                    @Parameter(name = "authorId", description = "Идентификатор автора задачи для фильтрации", examples = @ExampleObject(value = "<UUID>")),
                    @Parameter(name = "executorId", description = "Идентификатор исполнителя задачи для фильтрации", examples = @ExampleObject(value = "<UUID>")),
                    @Parameter(name = "page", description = "Номер страницы для пагинации", examples = @ExampleObject(value = "0")),
                    @Parameter(name = "size", description = "Размер страницы для пагинации", examples = @ExampleObject(value = "10"))
            },
            responses = {
                    @ApiResponse(responseCode = "200", description = "Успешный ответ",
                            content = @Content(mediaType = "application/json",
                                    schema = @Schema(implementation = TaskPage.class))),
                    @ApiResponse(responseCode = "400", description = "Некорректные параметры запроса")
            }
    )
    public ResponseEntity<TaskPage> getAllTasks(@RequestParam(required = false) String title,
                                                @RequestParam(required = false) String description,
                                                @RequestParam(required = false) String status,
                                                @RequestParam(required = false) String priority,
                                                @RequestParam(required = false) String authorId,
                                                @RequestParam(required = false) String executorId,
                                                @RequestParam(defaultValue = "0") int page,
                                                @RequestParam(defaultValue = "10") int size) {

        LOGGER.info("Получен запрос GET на получение всех задач с фильтрами - title: {}, description: {}, status: {}, priority: {}, authorId: {}, executorId: {}, page: {}, size: {}",
                title, description, status, priority, authorId, executorId, page, size);

        TaskFilterParameters filterParameters = TaskFilterParameters.createTaskFilterParameters(title, description, status, priority, authorId, executorId, page, size);

        TaskPage taskPage = taskService.getAllFiltered(filterParameters);

        return ResponseEntity.ok().body(taskPage);
    }

    @PostMapping("/tasks")
    @PreAuthorize("hasAnyAuthority('ADMIN')")
    @Operation(
            summary = "Создание новой задачи",
            description = "Позволяет создать новую задачу, предоставив данные для ее создания.",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Данные для создания задачи",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = TaskForm.class)
                    )
            ),
            responses = {
                    @ApiResponse(responseCode = "201", description = "Задача успешно создана",
                            content = @Content(mediaType = "application/json",
                                    schema = @Schema(implementation = TaskDto.class))),
                    @ApiResponse(responseCode = "400", description = "Некорректные данные для создания задачи")
            }
    )
    public ResponseEntity<TaskDto> addTask(@RequestBody @Valid TaskForm form) {
        LOGGER.info("Получен запрос POST на создание задачи. Данные задачи: {}", form);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(taskService.save(form));
    }

    @PatchMapping("/tasks/{id}")
    @PreAuthorize("hasAnyAuthority('ADMIN')")
    @Operation(
            summary = "Обновление задачи",
            description = "Обновляет задачу по ее ID, изменяя заголовок, описание, статус и приоритет.",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Данные для обновления задачи",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = TaskForm.class)
                    )
            ),
            responses = {
                    @ApiResponse(responseCode = "202", description = "Задача успешно обновлена",
                            content = @Content(mediaType = "application/json",
                                    schema = @Schema(implementation = TaskDto.class))),
                    @ApiResponse(responseCode = "400", description = "Некорректные данные для обновления задачи"),
                    @ApiResponse(responseCode = "404", description = "Задача не найдена")
            }
    )
    public ResponseEntity<TaskDto> updateTask(@PathVariable("id") UUID id,
                                              @RequestBody @Valid TaskForm form) {
        LOGGER.info("Получен запрос PATCH на обновление задачи с id: {}. Данные для обновления: {}", id, form);
        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(taskService.updateById(id, form));
    }

    @PatchMapping("/tasks/{id}/status")
    @PreAuthorize("hasAnyAuthority('ADMIN','COMMON_USER')")
    @Operation(
            summary = "Обновление статуса задачи",
            description = "Обновляет статус задачи по ее ID.",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Новый статус для обновления задачи",
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = TaskStatusForm.class)
                    )
            ),
            responses = {
                    @ApiResponse(responseCode = "202", description = "Статус задачи успешно обновлен",
                            content = @Content(mediaType = "application/json",
                                    schema = @Schema(implementation = TaskDto.class))),
                    @ApiResponse(responseCode = "400", description = "Некорректные данные для обновления статуса задачи"),
                    @ApiResponse(responseCode = "404", description = "Задача не найдена")
            }
    )
    public ResponseEntity<TaskDto> updateTaskStatus(@PathVariable("id") UUID id,
                                                    @RequestBody @Valid TaskStatusForm status) {
        LOGGER.info("Получен запрос PATCH на обновление статуса задачи с id: {}. Новый статус: {}", id, status);
        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(taskService.updateTaskStatus(id, status));
    }

    @DeleteMapping("/tasks/{id}")
    @PreAuthorize("hasAnyAuthority('ADMIN')")
    @Operation(
            summary = "Удаление задачи",
            description = "Удаляет задачу по ее ID.",
            responses = {
                    @ApiResponse(responseCode = "202", description = "Задача успешно удалена"),
                    @ApiResponse(responseCode = "404", description = "Задача не найдена")
            }
    )
    public ResponseEntity<?> deleteTask(@PathVariable("id") UUID id) {
        LOGGER.info("Получен запрос DELETE на удаление задачи с id: {}", id);
        taskService.deleteById(id);
        return ResponseEntity.status(HttpStatus.ACCEPTED).build();
    }

    @GetMapping("/account/{id}/tasks/created")
    @PreAuthorize("hasAnyAuthority('ADMIN','COMMON_USER')")
    @Operation(
            summary = "Получение списка задач конкретного автора по его ID переданному в запросе",
            description = "Возвращает список всех задач указанного автора с возможностью фильтрации по следующим параметрам:\n" +
                    "1. Заголовок задачи (title)\n" +
                    "2. Описание задачи (description)\n" +
                    "3. Статус задачи (status)\n" +
                    "4. Приоритет задачи (priority)\n" +
                    "5. Идентификатор исполнителя задачи (executorId)\n" +
                    "6. Номер страницы (page)\n" +
                    "7. Размер страницы (size)",
            parameters = {
                    @Parameter(name = "title", description = "Заголовок задачи для фильтрации", examples = @ExampleObject(value = "Рефакторинг")),
                    @Parameter(name = "description", description = "Описание задачи для фильтрации", examples = @ExampleObject(value = "Изменить код класса UserServiceImpl")),
                    @Parameter(name = "status", description = "Статус задачи для фильтрации", examples = @ExampleObject(value = "REVIEW")),
                    @Parameter(name = "priority", description = "Приоритет задачи для фильтрации", examples = @ExampleObject(value = "LOW")),
                    @Parameter(name = "executorId", description = "Идентификатор исполнителя задачи для фильтрации", examples = @ExampleObject(value = "<UUID>")),
                    @Parameter(name = "page", description = "Номер страницы для пагинации", examples = @ExampleObject(value = "0")),
                    @Parameter(name = "size", description = "Размер страницы для пагинации", examples = @ExampleObject(value = "10"))
            },
            responses = {
                    @ApiResponse(responseCode = "200", description = "Успешный ответ",
                            content = @Content(mediaType = "application/json",
                                    schema = @Schema(implementation = TaskPage.class))),
                    @ApiResponse(responseCode = "400", description = "Некорректные параметры запроса")
            }
    )
    public ResponseEntity<TaskPage> getAllAuthorTasks(@PathVariable("id") UUID id,
                                                      @RequestParam(required = false) String title,
                                                      @RequestParam(required = false) String description,
                                                      @RequestParam(required = false) String status,
                                                      @RequestParam(required = false) String priority,
                                                      @RequestParam(required = false) String executorId,
                                                      @RequestParam(defaultValue = "0") int page,
                                                      @RequestParam(defaultValue = "10") int size) {

        LOGGER.info("Получен запрос GET на получение задач, созданных автором с id: {} с фильтрами - title: {}, description: {}, status: {}, priority: {}, executorId: {}, page: {}, size: {}",
                id, title, description, status, priority, executorId, page, size);

        TaskFilterParameters filterParameters = TaskFilterParameters.createTaskFilterParameters(title, description, status, priority, String.valueOf(id), executorId, page, size);

        TaskPage taskPage = taskService.getAllFiltered(filterParameters);

        return ResponseEntity.ok().body(taskPage);
    }

    @GetMapping("/account/{id}/tasks/assigned")
    @PreAuthorize("hasAnyAuthority('ADMIN','COMMON_USER')")
    @Operation(
            summary = "Получение списка задач конкретного исполнителя по его ID переданному в запросе",
            description = "Возвращает список всех задач указанного исполнителя с возможностью фильтрации по следующим параметрам:\n" +
                    "1. Заголовок задачи (title)\n" +
                    "2. Описание задачи (description)\n" +
                    "3. Статус задачи (status)\n" +
                    "4. Приоритет задачи (priority)\n" +
                    "5. Идентификатор автора задачи (authorId)\n" +
                    "6. Номер страницы (page)\n" +
                    "7. Размер страницы (size)",
            parameters = {
                    @Parameter(name = "title", description = "Заголовок задачи для фильтрации", examples = @ExampleObject(value = "Рефакторинг")),
                    @Parameter(name = "description", description = "Описание задачи для фильтрации", examples = @ExampleObject(value = "Изменить код класса UserServiceImpl")),
                    @Parameter(name = "status", description = "Статус задачи для фильтрации", examples = @ExampleObject(value = "REVIEW")),
                    @Parameter(name = "priority", description = "Приоритет задачи для фильтрации", examples = @ExampleObject(value = "LOW")),
                    @Parameter(name = "authorId", description = "Идентификатор автора задачи для фильтрации", examples = @ExampleObject(value = "<UUID>")),
                    @Parameter(name = "page", description = "Номер страницы для пагинации", examples = @ExampleObject(value = "0")),
                    @Parameter(name = "size", description = "Размер страницы для пагинации", examples = @ExampleObject(value = "10"))
            },
            responses = {
                    @ApiResponse(responseCode = "200", description = "Успешный ответ",
                            content = @Content(mediaType = "application/json",
                                    schema = @Schema(implementation = TaskPage.class))),
                    @ApiResponse(responseCode = "400", description = "Некорректные параметры запроса")
            }
    )
    public ResponseEntity<TaskPage> getAllExecutorTasks(@PathVariable("id") UUID id,
                                                        @RequestParam(required = false) String title,
                                                        @RequestParam(required = false) String description,
                                                        @RequestParam(required = false) String status,
                                                        @RequestParam(required = false) String priority,
                                                        @RequestParam(required = false) String authorId,
                                                        @RequestParam(defaultValue = "0") int page,
                                                        @RequestParam(defaultValue = "10") int size) {

        LOGGER.info("Получен запрос GET на получение задач, назначенных исполнителю с id: {} с фильтрами - title: {}, description: {}, status: {}, priority: {}, authorId: {}, page: {}, size: {}",
                id, title, description, status, priority, authorId, page, size);

        TaskFilterParameters filterParameters = TaskFilterParameters.createTaskFilterParameters(title, description, status, priority, authorId, String.valueOf(id), page, size);

        TaskPage taskPage = taskService.getAllFiltered(filterParameters);

        return ResponseEntity.ok().body(taskPage);
    }
}
