package by.dasayoper.taskmanager.service.impl;

import by.dasayoper.taskmanager.dto.TaskDto;
import by.dasayoper.taskmanager.dto.form.TaskForm;
import by.dasayoper.taskmanager.dto.form.TaskStatusForm;
import by.dasayoper.taskmanager.dto.page.TaskPage;
import by.dasayoper.taskmanager.dto.util.TaskFilterParameters;
import by.dasayoper.taskmanager.exception.TaskNotFoundException;
import by.dasayoper.taskmanager.exception.UserAccountNotFoundException;
import by.dasayoper.taskmanager.model.Account;
import by.dasayoper.taskmanager.model.BaseEntity;
import by.dasayoper.taskmanager.model.Task;
import by.dasayoper.taskmanager.repository.AccountRepository;
import by.dasayoper.taskmanager.repository.TaskRepository;
import by.dasayoper.taskmanager.service.SecurityService;
import by.dasayoper.taskmanager.service.TaskService;
import by.dasayoper.taskmanager.specification.TaskSpecification;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.UUID;

import static by.dasayoper.taskmanager.dto.TaskDto.from;

@Service
@RequiredArgsConstructor
public class TaskServiceImpl implements TaskService {

    private final TaskRepository taskRepository;
    private final SecurityService securityService;
    private final AccountRepository accountRepository;

    private final Logger LOGGER = LoggerFactory.getLogger(this.getClass());

    /**
     * Получение задачи по идентификатору.
     *
     * @param id уникальный идентификатор задачи.
     * @return объект {@link TaskDto}, содержащий данные задачи.
     * @throws TaskNotFoundException если задача с указанным id не найдена.
     */
    @Override
    public TaskDto getById(UUID id) {
        LOGGER.info("Попытка получения задачи с id: {}", id);
        Task task = findTaskById(id);
        LOGGER.info("Задача с id: {} успешно найдена", id);
        return from(task);
    }

    /**
     * Получение списка всех задач.
     *
     * @return список всех задач в виде {@link TaskDto}.
     */
    @Override
    public List<TaskDto> getAll() {
        LOGGER.info("Запрос на получение всех задач");
        List<TaskDto> tasks = from(taskRepository.findAll());
        LOGGER.info("Получено {} задач", tasks.size());
        return tasks;
    }

    /**
     * Получение задач с фильтрацией и пагинацией.
     *
     * @param filterParameters параметры фильтрации задач {@link TaskFilterParameters}.
     * @return объект {@link TaskPage}, содержащий список задач в виде {@link TaskDto} и данные о пагинации.
     */
    @Override
    public TaskPage getAllFiltered(TaskFilterParameters filterParameters) {
        LOGGER.info("Запрос на получение задач с фильтрацией по параметрам: {}", filterParameters);
        Specification<Task> specification = buildTaskSpecification(filterParameters);

        Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
        Page<Task> taskPage = taskRepository.findAll(specification, pageable);

        LOGGER.info("Найдено {} задач, всего страниц: {}, элементов: {}",
                taskPage.getContent().size(),
                taskPage.getTotalPages(),
                taskPage.getTotalElements());

        return TaskPage.builder()
                .tasks(from(taskPage.getContent()))
                .totalPages(taskPage.getTotalPages())
                .totalElements(taskPage.getTotalElements())
                .currentPage(pageable.getPageNumber())
                .build();
    }

    /**
     * Добавление новой задачи.
     *
     * @param form   данные для создания задачи.
     * @return объект {@link TaskDto}, содержащий данные сохраненной задачи.
     * @throws AccessDeniedException если пользователь не является администратором.
     */
    @Override
    public TaskDto save(TaskForm form) {
        LOGGER.info("Попытка добавления новой задачи");
        Account authorizedAccount = securityService.getAuthorizedAccount();

        if (authorizedAccount.getRole().equals(Account.Role.ADMIN)) {
            Task newTask = Task.builder()
                    .title(form.getTitle())
                    .description(form.getDescription())
                    .status(Task.TaskStatus.valueOf(form.getStatus()))
                    .priority(Task.TaskPriority.valueOf(form.getPriority()))
                    .state(BaseEntity.State.ACTIVE)
                    .author(securityService.getAuthorizedAccount())
                    .executor(form.getExecutorId() != null ? findAccountById(UUID.fromString(form.getExecutorId())) : null)
                    .comments(new HashSet<>())
                    .build();

            TaskDto savedTask = from(taskRepository.save(newTask));

            LOGGER.info("Задача успешно добавлена с id: {}", savedTask.getId());
            return savedTask;
        } else {
            LOGGER.warn("Недостаточно прав создания задач");
            throw new AccessDeniedException("Вы не являетесь администратором и не можете создавать задачи");
        }
    }

    /**
     * Обновление задачи по идентификатору.
     * Данный метод доступен только пользователям с ролью {@link Account.Role#ADMIN}.
     *
     * @param id          уникальный идентификатор задачи.
     * @param form данные для обновления задачи {@link TaskForm}.
     * @return объект {@link TaskDto}, содержащий данные обновленной задачи.
     * @throws TaskNotFoundException если задача с указанным id не найдена.
     */
    @Override
    public TaskDto updateById(UUID id, TaskForm form) {
        LOGGER.info("Запрос на обновление задачи с id: {}", id);
        Task task = findTaskById(id);
        
        task.setTitle(form.getTitle());
        task.setDescription(form.getDescription() != null ? form.getDescription() : task.getDescription());
        task.setStatus(Task.TaskStatus.valueOf(form.getStatus()));
        task.setPriority(Task.TaskPriority.valueOf(form.getPriority()));
        task.setExecutor(form.getExecutorId() != null ? findAccountById(UUID.fromString(form.getExecutorId())) : task.getExecutor());

        TaskDto updatedTask = from(taskRepository.save(task));
        LOGGER.info("Задача с id: {} успешна обновлена", updatedTask.getId());
        return updatedTask;
    }

    /**
     * Обновление задачи по идентификатору.
     * Данный метод доступен только пользователям с ролью {@link Account.Role#ADMIN}.
     *
     * @param id          уникальный идентификатор задачи.
     * @throws TaskNotFoundException если задача с указанным id не найдена.
     */
    @Override
    public void deleteById(UUID id) {
        LOGGER.info("Запрос на удаление задачи с id: {}", id);
        Task task = findTaskById(id);

        task.setState(BaseEntity.State.DELETED);

        taskRepository.save(task);
        LOGGER.info("State задачи с id: {} изменен на 'DELETED'", id);
    }

    /**
     * Обновление статуса задачи по идентификатору.
     * Данный метод доступен администраторам и исполнителям задачи.
     *
     * @param id          уникальный идентификатор задачи.
     * @param status данные для изменения статуса {@link TaskStatusForm}
     * @return объект {@link TaskDto}, содержащий данные обновленной задачи.
     * @throws TaskNotFoundException если задача с указанным id не найдена.
     * @throws AccessDeniedException если пользователь не является администратором.
     *
     */
    @Override
    public TaskDto updateTaskStatus(UUID id, TaskStatusForm status) {
        LOGGER.info("Запрос на обновление статуса задачи с id: {}", id);
        Task task = findTaskById(id);

        Account authorizedAccount = securityService.getAuthorizedAccount();

        if (task.getExecutor().equals(authorizedAccount) || authorizedAccount.getRole().equals(Account.Role.ADMIN)) {
            task.setStatus(Task.TaskStatus.valueOf(status.getStatus()));

            TaskDto updatedTask = from(taskRepository.save(task));
            LOGGER.info("Статус задачи с id: {} успешно обновлен на: {}", updatedTask.getId(), updatedTask.getStatus());
            return updatedTask;
        } else {
            throw new AccessDeniedException("Вы не являетесь администратором или исполнителем задачи: " + id + " и не можете изменить ее статус");
        }
    }

    /**
     * Вспомогательный метод для поиска задачи по идентификатору.
     *
     * @param id уникальный идентификатор задачи.
     * @return найденный объект {@link Task}.
     * @throws TaskNotFoundException если задача с указанным id не найдена.
     */
    private Task findTaskById(UUID id) {
        LOGGER.debug("Попытка получения задачи с id: {}", id);
        return taskRepository.findById(id)
                .orElseThrow(() -> {
                    LOGGER.error("Задача с id: {} не найдена.", id);
                    return new TaskNotFoundException("Задача с id: " + id + " не найдена");
                });
    }

    /**
     * Вспомогательный метод для поиска аккаунта по идентификатору.
     *
     * @param id уникальный идентификатор аккаунта.
     * @return найденный объект {@link Account}.
     * @throws UserAccountNotFoundException если аккаунт с указанным id не найден.
     */
    private Account findAccountById(UUID id) {
        LOGGER.debug("Попытка получения аккаунта с id: {}", id);
        return accountRepository.findById(id)
                .orElseThrow(() -> {
                    LOGGER.error("Аккаунт с id: {} не найден", id);
                    return new UserAccountNotFoundException("Аккаунт с id: " + id + " не найден");
                });
    }

    /**
     * Вспомогательный метод для создания спецификации для фильтрации задач.
     *
     * @param filterParameters параметры фильтрации задач {@link TaskFilterParameters}.
     * @return объект {@link Specification<Task>} для поиска.
     */
    private Specification<Task> buildTaskSpecification(TaskFilterParameters filterParameters) {
        LOGGER.debug("Создание спецификации для фильтрации: {}", filterParameters);

        Specification<Task> specification = Specification.where(TaskSpecification.notDeleted());

        if (filterParameters.getTitle() != null && !filterParameters.getTitle().isBlank()) {
            specification = specification.and(TaskSpecification.titleContains(filterParameters.getTitle()));
        }

        if (filterParameters.getDescription() != null && !filterParameters.getDescription().isBlank()) {
            specification = specification.and(TaskSpecification.descriptionContains(filterParameters.getDescription()));
        }

        if (filterParameters.getStatus() != null && !filterParameters.getStatus().isBlank()) {
            try {
                Task.TaskStatus status = Task.TaskStatus.valueOf(filterParameters.getStatus().toUpperCase());
                specification = specification.and(TaskSpecification.hasStatus(status));
            } catch (IllegalArgumentException e) {
                LOGGER.warn("Неверный формат значения для статуса: {}", filterParameters.getStatus());
            }
        }

        if (filterParameters.getPriority() != null && !filterParameters.getPriority().isBlank()) {
            try {
                Task.TaskPriority priority = Task.TaskPriority.valueOf(filterParameters.getPriority().toUpperCase());
                specification = specification.and(TaskSpecification.hasPriority(priority));
            } catch (IllegalArgumentException e) {
                LOGGER.warn("Неверный формат значения для приоритета: {}", filterParameters.getPriority());
            }
        }

        if (filterParameters.getAuthorId() != null) {
            try {
                UUID authorId = UUID.fromString(filterParameters.getAuthorId());
                specification = specification.and(TaskSpecification.hasAuthor(authorId));
            } catch (IllegalArgumentException e) {
                LOGGER.warn("Неверный формат UUID для authorId: {}", filterParameters.getAuthorId());
            }
        }

        if (filterParameters.getExecutorId() != null) {
            try {
                UUID executorId = UUID.fromString(filterParameters.getExecutorId());
                specification = specification.and(TaskSpecification.hasExecutor(executorId));
            } catch (IllegalArgumentException e) {
                LOGGER.warn("Неверный формат UUID для executorId: {}", filterParameters.getExecutorId());
            }
        }

        LOGGER.debug("Спецификация создана");
        return specification;
    }
}
