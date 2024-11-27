package by.dasayoper.taskmanager.service;

import by.dasayoper.taskmanager.dto.TaskDto;
import by.dasayoper.taskmanager.dto.form.TaskForm;
import by.dasayoper.taskmanager.dto.form.TaskStatusForm;
import by.dasayoper.taskmanager.dto.page.TaskPage;
import by.dasayoper.taskmanager.dto.util.TaskFilterParameters;
import by.dasayoper.taskmanager.exception.TaskNotFoundException;
import by.dasayoper.taskmanager.model.Account;
import by.dasayoper.taskmanager.model.BaseEntity;
import by.dasayoper.taskmanager.model.Task;
import by.dasayoper.taskmanager.repository.AccountRepository;
import by.dasayoper.taskmanager.repository.TaskRepository;
import by.dasayoper.taskmanager.service.impl.TaskServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.access.AccessDeniedException;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

public class TaskServiceImplTest {

    @Mock
    private TaskRepository taskRepository;

    @Mock
    private SecurityService securityService;

    @Mock
    private AccountRepository accountRepository;

    @InjectMocks
    private TaskServiceImpl taskService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Nested
    @DisplayName("getById() is working")
    class GetByIdTest {
        @Test
        void getById_shouldReturnTask_whenTaskExists() {
            UUID taskId = UUID.randomUUID();
            Task task = Task.builder()
                    .id(taskId)
                    .title("Task 1")
                    .description("Description 1")
                    .status(Task.TaskStatus.NEW)
                    .priority(Task.TaskPriority.MEDIUM)
                    .state(BaseEntity.State.ACTIVE)
                    .author(Account.builder().id(UUID.randomUUID()).build())
                    .executor(Account.builder().id(UUID.randomUUID()).build())
                    .comments(Set.of())
                    .build();

            when(taskRepository.findById(taskId)).thenReturn(Optional.of(task));

            TaskDto taskDto = taskService.getById(taskId);

            assertNotNull(taskDto);
            assertEquals("Task 1", taskDto.getTitle());
        }

        @Test
        void getById_shouldThrowException_whenTaskDoesNotExist() {
            UUID taskId = UUID.randomUUID();

            when(taskRepository.findById(taskId)).thenReturn(Optional.empty());

            assertThrows(TaskNotFoundException.class, () -> taskService.getById(taskId));
        }
    }

    @Test
    void getAll_shouldReturnAllTasks() {
        List<Task> tasks = List.of(
                Task.builder()
                        .id(UUID.randomUUID())
                        .title("Task 1")
                        .description("Description 1")
                        .status(Task.TaskStatus.NEW)
                        .priority(Task.TaskPriority.MEDIUM)
                        .state(BaseEntity.State.ACTIVE)
                        .author(Account.builder().id(UUID.randomUUID()).build())
                        .executor(Account.builder().id(UUID.randomUUID()).build())
                        .comments(Set.of())
                        .build(),
                Task.builder()
                        .id(UUID.randomUUID())
                        .title("Task 2")
                        .description("Description 2")
                        .status(Task.TaskStatus.ASSIGNED)
                        .priority(Task.TaskPriority.HIGH)
                        .state(BaseEntity.State.ACTIVE)
                        .author(Account.builder().id(UUID.randomUUID()).build())
                        .executor(Account.builder().id(UUID.randomUUID()).build())
                        .comments(Set.of())
                        .build()
        );

        when(taskRepository.findAll()).thenReturn(tasks);

        List<TaskDto> taskDtoList = taskService.getAll();

        assertNotNull(taskDtoList);
        assertEquals(2, taskDtoList.size());

        TaskDto firstTaskDto = taskDtoList.get(0);
        assertEquals("Task 1", firstTaskDto.getTitle());

        TaskDto secondTaskDto = taskDtoList.get(1);
        assertEquals("Task 2", secondTaskDto.getTitle());
    }

    @Nested
    @DisplayName("getAllFiltered() is working")
    class GetAllFilteredTests {

        @Test
        void getAllFiltered_shouldReturnAllTasks_WhenNoFiltersApplied() {
            List<Task> tasks = List.of(
                    Task.builder()
                            .id(UUID.randomUUID())
                            .title("Task 1")
                            .description("Description 1")
                            .status(Task.TaskStatus.NEW)
                            .priority(Task.TaskPriority.MEDIUM)
                            .state(BaseEntity.State.ACTIVE)
                            .author(Account.builder().id(UUID.randomUUID()).build())
                            .executor(Account.builder().id(UUID.randomUUID()).build())
                            .comments(Set.of())
                            .build(),
                    Task.builder()
                            .id(UUID.randomUUID())
                            .title("Task 2")
                            .description("Description 2")
                            .status(Task.TaskStatus.ASSIGNED)
                            .priority(Task.TaskPriority.HIGH)
                            .state(BaseEntity.State.ACTIVE)
                            .author(Account.builder().id(UUID.randomUUID()).build())
                            .executor(Account.builder().id(UUID.randomUUID()).build())
                            .comments(Set.of())
                            .build()
            );

            TaskFilterParameters filterParameters = TaskFilterParameters.createTaskFilterParameters(null, null, null, null, null, null, 0, 10);

            Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
            Page<Task> taskPage = new PageImpl<>(tasks, pageable, tasks.size());
            when(taskRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(taskPage);

            TaskPage result = taskService.getAllFiltered(filterParameters);

            assertNotNull(result);
            assertEquals(2, result.getTasks().size());
            assertEquals(1, result.getTotalPages());
        }

        @Test
        void getAllFiltered_shouldFilterTasks_ByTitle() {
            List<Task> tasks = List.of(
                    Task.builder()
                            .id(UUID.randomUUID())
                            .title("Filtered Task")
                            .description("Description")
                            .status(Task.TaskStatus.NEW)
                            .priority(Task.TaskPriority.MEDIUM)
                            .state(BaseEntity.State.ACTIVE)
                            .author(Account.builder().id(UUID.randomUUID()).build())
                            .executor(Account.builder().id(UUID.randomUUID()).build())
                            .comments(Set.of())
                            .build()
            );

            TaskFilterParameters filterParameters = TaskFilterParameters.createTaskFilterParameters("Filt", null, null, null, null, null, 0, 10);

            Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
            Page<Task> taskPage = new PageImpl<>(tasks, pageable, tasks.size());
            when(taskRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(taskPage);

            TaskPage result = taskService.getAllFiltered(filterParameters);

            assertNotNull(result);
            assertEquals(1, result.getTasks().size());
            assertEquals("Filtered Task", result.getTasks().get(0).getTitle());
        }

        @Test
        void getAllFiltered_shouldFilterTasks_ByDescription() {
            List<Task> tasks = List.of(
                    Task.builder()
                            .id(UUID.randomUUID())
                            .title("Task 1")
                            .description("Filtered Description")
                            .status(Task.TaskStatus.NEW)
                            .priority(Task.TaskPriority.MEDIUM)
                            .state(BaseEntity.State.ACTIVE)
                            .author(Account.builder().id(UUID.randomUUID()).build())
                            .executor(Account.builder().id(UUID.randomUUID()).build())
                            .comments(Set.of())
                            .build()
            );

            TaskFilterParameters filterParameters = TaskFilterParameters.createTaskFilterParameters(null, "Filt", null, null, null, null, 0, 10);

            Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
            Page<Task> taskPage = new PageImpl<>(tasks, pageable, tasks.size());
            when(taskRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(taskPage);

            TaskPage result = taskService.getAllFiltered(filterParameters);

            assertNotNull(result);
            assertEquals(1, result.getTasks().size());
            assertEquals("Filtered Description", result.getTasks().get(0).getDescription());
        }

        @Test
        void getAllFiltered_shouldFilterTasks_ByStatus() {
            List<Task> tasks = List.of(
                    Task.builder()
                            .id(UUID.randomUUID())
                            .title("Task 1")
                            .description("Description")
                            .status(Task.TaskStatus.ASSIGNED)
                            .priority(Task.TaskPriority.MEDIUM)
                            .state(BaseEntity.State.ACTIVE)
                            .author(Account.builder().id(UUID.randomUUID()).build())
                            .executor(Account.builder().id(UUID.randomUUID()).build())
                            .comments(Set.of())
                            .build()
            );

            TaskFilterParameters filterParameters = TaskFilterParameters.createTaskFilterParameters(null, null, "ASSIGNED", null, null, null, 0, 10);

            Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
            Page<Task> taskPage = new PageImpl<>(tasks, pageable, tasks.size());
            when(taskRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(taskPage);

            TaskPage result = taskService.getAllFiltered(filterParameters);

            assertNotNull(result);
            assertEquals(1, result.getTasks().size());
            assertEquals(Task.TaskStatus.ASSIGNED, Task.TaskStatus.valueOf(result.getTasks().get(0).getStatus()));
        }

        @Test
        void getAllFiltered_shouldFilterTasks_ByPriority() {
            List<Task> tasks = List.of(
                    Task.builder()
                            .id(UUID.randomUUID())
                            .title("Task 1")
                            .description("Description")
                            .status(Task.TaskStatus.NEW)
                            .priority(Task.TaskPriority.HIGH)
                            .state(BaseEntity.State.ACTIVE)
                            .author(Account.builder().id(UUID.randomUUID()).build())
                            .executor(Account.builder().id(UUID.randomUUID()).build())
                            .comments(Set.of())
                            .build()
            );

            TaskFilterParameters filterParameters = TaskFilterParameters.createTaskFilterParameters(null, null, null, "HIGH", null, null, 0, 10);

            Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
            Page<Task> taskPage = new PageImpl<>(tasks, pageable, tasks.size());
            when(taskRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(taskPage);

            TaskPage result = taskService.getAllFiltered(filterParameters);

            assertNotNull(result);
            assertEquals(1, result.getTasks().size());
            assertEquals(Task.TaskPriority.HIGH, Task.TaskPriority.valueOf(result.getTasks().get(0).getPriority()));
        }

        @Test
        void getAllFiltered_shouldFilterTasks_ByAuthorId() {
            UUID authorId = UUID.randomUUID();
            List<Task> tasks = List.of(
                    Task.builder()
                            .id(UUID.randomUUID())
                            .title("Task 1")
                            .description("Description")
                            .status(Task.TaskStatus.NEW)
                            .priority(Task.TaskPriority.MEDIUM)
                            .state(BaseEntity.State.ACTIVE)
                            .author(Account.builder().id(authorId).build())
                            .executor(Account.builder().id(UUID.randomUUID()).build())
                            .comments(Set.of())
                            .build()
            );

            TaskFilterParameters filterParameters = TaskFilterParameters.createTaskFilterParameters(null, null, null, null, authorId.toString(), null, 0, 10);

            Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
            Page<Task> taskPage = new PageImpl<>(tasks, pageable, tasks.size());
            when(taskRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(taskPage);

            TaskPage result = taskService.getAllFiltered(filterParameters);

            assertNotNull(result);
            assertEquals(1, result.getTasks().size());
            assertEquals(authorId, result.getTasks().get(0).getAuthorId());
        }

        @Test
        void getAllFiltered_shouldFilterTasks_ByExecutorId() {
            UUID executorId = UUID.randomUUID();
            List<Task> tasks = List.of(
                    Task.builder()
                            .id(UUID.randomUUID())
                            .title("Task 1")
                            .description("Description")
                            .status(Task.TaskStatus.NEW)
                            .priority(Task.TaskPriority.MEDIUM)
                            .state(BaseEntity.State.ACTIVE)
                            .author(Account.builder().id(UUID.randomUUID()).build())
                            .executor(Account.builder().id(executorId).build())
                            .comments(Set.of())
                            .build()
            );

            TaskFilterParameters filterParameters = TaskFilterParameters.createTaskFilterParameters(null, null, null, null, null, executorId.toString(), 0, 10);

            Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
            Page<Task> taskPage = new PageImpl<>(tasks, pageable, tasks.size());
            when(taskRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(taskPage);

            TaskPage result = taskService.getAllFiltered(filterParameters);

            assertNotNull(result);
            assertEquals(1, result.getTasks().size());
            assertEquals(executorId, result.getTasks().get(0).getExecutorId());
        }
    }

    @Nested
    @DisplayName("save() is working")
    class SaveTest {
        @Test
        void save_shouldSaveTask_whenUserIsAdmin() {
            TaskForm form = TaskForm.builder()
                    .title("New Task")
                    .description("Description")
                    .status("NEW")
                    .priority("MEDIUM")
                    .executorId(UUID.randomUUID().toString())
                    .build();

            Account authorizedAccount = Account.builder()
                    .id(UUID.randomUUID())
                    .role(Account.Role.ADMIN)
                    .build();

            Account executorAccount = Account.builder()
                    .id(UUID.fromString(form.getExecutorId()))
                    .build();

            Task newTask = Task.builder()
                    .title(form.getTitle())
                    .description(form.getDescription())
                    .status(Task.TaskStatus.valueOf(form.getStatus()))
                    .priority(Task.TaskPriority.valueOf(form.getPriority()))
                    .state(BaseEntity.State.ACTIVE)
                    .author(authorizedAccount)
                    .executor(executorAccount)
                    .comments(Set.of())
                    .build();

            when(securityService.getAuthorizedAccount()).thenReturn(authorizedAccount);
            when(accountRepository.findById(UUID.fromString(form.getExecutorId()))).thenReturn(Optional.of(executorAccount));
            when(taskRepository.save(any(Task.class))).thenReturn(newTask);

            TaskDto savedTask = taskService.save(form);

            assertNotNull(savedTask);
            assertEquals("New Task", savedTask.getTitle());
        }

        @Test
        void save_shouldThrowException_whenUserIsNotAdmin() {
            TaskForm form = TaskForm.builder()
                    .title("New Task")
                    .description("Description")
                    .status("NEW")
                    .priority("MEDIUM")
                    .executorId(UUID.randomUUID().toString())
                    .build();

            Account authorizedAccount = Account.builder()
                    .id(UUID.randomUUID())
                    .role(Account.Role.COMMON_USER)
                    .build();

            when(securityService.getAuthorizedAccount()).thenReturn(authorizedAccount);

            assertThrows(AccessDeniedException.class, () -> taskService.save(form));
        }
    }

    @Nested
    @DisplayName("updateById() is working")
    class UpdateByIdTest {
        @Test
        void updateById_shouldUpdateTask_whenTaskExists() {
            UUID taskId = UUID.randomUUID();
            TaskForm form = TaskForm.builder()
                    .title("Updated Task")
                    .description("Updated Description")
                    .status("ASSIGNED")
                    .priority("HIGH")
                    .executorId(UUID.randomUUID().toString())
                    .build();

            Task task = Task.builder()
                    .id(taskId)
                    .title("Old Task")
                    .description("Old Description")
                    .status(Task.TaskStatus.NEW)
                    .priority(Task.TaskPriority.MEDIUM)
                    .state(BaseEntity.State.ACTIVE)
                    .author(Account.builder().id(UUID.randomUUID()).build())
                    .executor(Account.builder().id(UUID.randomUUID()).build())
                    .comments(Set.of())
                    .build();

            Account executorAccount = Account.builder()
                    .id(UUID.fromString(form.getExecutorId()))
                    .build();

            when(taskRepository.findById(taskId)).thenReturn(Optional.of(task));
            when(accountRepository.findById(UUID.fromString(form.getExecutorId()))).thenReturn(Optional.of(executorAccount));
            when(taskRepository.save(any(Task.class))).thenReturn(task);

            TaskDto updatedTask = taskService.updateById(taskId, form);

            assertNotNull(updatedTask);
            assertEquals("Updated Task", updatedTask.getTitle());
            assertEquals("Updated Description", updatedTask.getDescription());
            assertEquals(Task.TaskStatus.ASSIGNED, Task.TaskStatus.valueOf(updatedTask.getStatus()));
            assertEquals(Task.TaskPriority.HIGH, Task.TaskPriority.valueOf(updatedTask.getPriority()));
        }

        @Test
        void updateById_shouldThrowException_whenTaskDoesNotExist() {
            UUID taskId = UUID.randomUUID();
            TaskForm form = TaskForm.builder()
                    .title("Updated Task")
                    .description("Updated Description")
                    .status("ASSIGNED")
                    .priority("HIGH")
                    .executorId(UUID.randomUUID().toString())
                    .build();

            when(taskRepository.findById(taskId)).thenReturn(Optional.empty());

            assertThrows(TaskNotFoundException.class, () -> taskService.updateById(taskId, form));
        }
    }

    @Nested
    @DisplayName("deleteById() is working")
    class DeleteByIdTest {
        @Test
        void deleteById_shouldDeleteTask_whenTaskExists() {
            UUID taskId = UUID.randomUUID();
            Task task = Task.builder()
                    .id(taskId)
                    .title("Task 1")
                    .description("Description")
                    .status(Task.TaskStatus.NEW)
                    .priority(Task.TaskPriority.MEDIUM)
                    .state(BaseEntity.State.ACTIVE)
                    .author(Account.builder().id(UUID.randomUUID()).build())
                    .executor(Account.builder().id(UUID.randomUUID()).build())
                    .comments(Set.of())
                    .build();

            when(taskRepository.findById(taskId)).thenReturn(Optional.of(task));
            when(taskRepository.save(any(Task.class))).thenReturn(task);

            taskService.deleteById(taskId);

            assertEquals(BaseEntity.State.DELETED, task.getState());
        }

        @Test
        void deleteById_shouldThrowException_whenTaskDoesNotExist() {
            UUID taskId = UUID.randomUUID();

            when(taskRepository.findById(taskId)).thenReturn(Optional.empty());

            assertThrows(TaskNotFoundException.class, () -> taskService.deleteById(taskId));
        }
    }

    @Nested
    @DisplayName("updateTaskStatus() is working")
    class UpdateTaskStatusTest {
        @Test
        void updateTaskStatus_shouldUpdateStatus_whenUserIsAdminOrExecutor() {
            UUID taskId = UUID.randomUUID();
            TaskStatusForm statusForm = TaskStatusForm.builder()
                    .status("ASSIGNED")
                    .build();

            Task task = Task.builder()
                    .id(taskId)
                    .title("Task 1")
                    .description("Description")
                    .status(Task.TaskStatus.NEW)
                    .priority(Task.TaskPriority.MEDIUM)
                    .state(BaseEntity.State.ACTIVE)
                    .author(Account.builder().id(UUID.randomUUID()).build())
                    .executor(Account.builder().id(UUID.randomUUID()).build())
                    .comments(Set.of())
                    .build();

            Account authorizedAccount = Account.builder()
                    .id(task.getExecutor().getId())
                    .role(Account.Role.ADMIN)
                    .build();

            when(taskRepository.findById(taskId)).thenReturn(Optional.of(task));
            when(securityService.getAuthorizedAccount()).thenReturn(authorizedAccount);
            when(taskRepository.save(any(Task.class))).thenReturn(task);

            TaskDto updatedTask = taskService.updateTaskStatus(taskId, statusForm);

            assertNotNull(updatedTask);
            assertEquals(Task.TaskStatus.ASSIGNED, Task.TaskStatus.valueOf(updatedTask.getStatus()));
        }

        @Test
        void updateTaskStatus_shouldThrowException_whenUserIsNotAdminOrExecutor() {
            UUID taskId = UUID.randomUUID();
            TaskStatusForm statusForm = TaskStatusForm.builder()
                    .status("ASSIGNED")
                    .build();

            Task task = Task.builder()
                    .id(taskId)
                    .title("Task 1")
                    .description("Description")
                    .status(Task.TaskStatus.NEW)
                    .priority(Task.TaskPriority.MEDIUM)
                    .state(BaseEntity.State.ACTIVE)
                    .author(Account.builder().id(UUID.randomUUID()).build())
                    .executor(Account.builder().id(UUID.randomUUID()).build())
                    .comments(Set.of())
                    .build();

            Account authorizedAccount = Account.builder()
                    .id(UUID.randomUUID())
                    .role(Account.Role.COMMON_USER)
                    .build();

            when(taskRepository.findById(taskId)).thenReturn(Optional.of(task));
            when(securityService.getAuthorizedAccount()).thenReturn(authorizedAccount);

            assertThrows(AccessDeniedException.class, () -> taskService.updateTaskStatus(taskId, statusForm));
        }
    }
}
