package by.dasayoper.taskmanager.controller;

import by.dasayoper.taskmanager.dto.TaskDto;
import by.dasayoper.taskmanager.dto.form.TaskForm;
import by.dasayoper.taskmanager.dto.form.TaskStatusForm;
import by.dasayoper.taskmanager.dto.page.TaskPage;
import by.dasayoper.taskmanager.dto.util.TaskFilterParameters;
import by.dasayoper.taskmanager.exception.TaskNotFoundException;
import by.dasayoper.taskmanager.service.TaskService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class TaskControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private TaskService taskService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Nested
    @DisplayName("getTask() is working")
    class GetTask {
        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void getTask_ShouldReturnTask_WhenTaskExists() throws Exception {
            UUID taskId = UUID.randomUUID();
            TaskDto task = TaskDto.builder()
                    .id(taskId)
                    .title("Task 1")
                    .description("Description 1")
                    .status("NEW")
                    .priority("MEDIUM")
                    .authorId(UUID.randomUUID())
                    .executorId(UUID.randomUUID())
                    .build();

            when(taskService.getById(taskId)).thenReturn(task);

            mockMvc.perform(get("/tasks/" + taskId))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(taskId.toString()))
                    .andExpect(jsonPath("$.title").value("Task 1"))
                    .andExpect(jsonPath("$.status").value("NEW"));
        }

        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void getTask_ShouldReturn404NotFound_WhenTaskDoesNotExist() throws Exception {
            UUID taskId = UUID.randomUUID();

            when(taskService.getById(taskId)).thenThrow(new TaskNotFoundException("Task not found with id: " + taskId));

            mockMvc.perform(get("/tasks/" + taskId))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.code").value(404))
                    .andExpect(jsonPath("$.status").value("NOT_FOUND"))
                    .andExpect(jsonPath("$.message").value("Task not found with id: " + taskId));
        }
    }

    @Nested
    @DisplayName("getAllTasks() is working")
    class GetAllTasks {

        private List<TaskDto> tasks;

        @BeforeEach
        void setUp() {
            tasks = Arrays.asList(
                    TaskDto.builder()
                            .id(UUID.randomUUID())
                            .title("Task 1")
                            .description("Description 1")
                            .status("NEW")
                            .priority("MEDIUM")
                            .authorId(UUID.randomUUID())
                            .executorId(UUID.randomUUID())
                            .build(),
                    TaskDto.builder()
                            .id(UUID.randomUUID())
                            .title("Task 2")
                            .description("Description 2")
                            .status("ASSIGNED")
                            .priority("HIGH")
                            .authorId(UUID.randomUUID())
                            .executorId(UUID.randomUUID())
                            .build()
            );
        }

        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void getAllTasks_ShouldReturnFilteredTasks_WhenFilteringByTitle() throws Exception {
            TaskFilterParameters filterParameters = TaskFilterParameters.createTaskFilterParameters("Task", null, null, null, null, null, 0, 10);
            TaskPage taskPage = new TaskPage(tasks, 1, 2L, 0);

            when(taskService.getAllFiltered(any(TaskFilterParameters.class))).thenReturn(taskPage);

            mockMvc.perform(get("/tasks")
                            .param("title", "Task")
                            .param("size", "10")
                            .param("page", "0"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.tasks.length()").value(2))
                    .andExpect(jsonPath("$.tasks[0].title").value("Task 1"))
                    .andExpect(jsonPath("$.tasks[1].title").value("Task 2"))
                    .andExpect(jsonPath("$.totalElements").value(2))
                    .andExpect(jsonPath("$.totalPages").value(1))
                    .andExpect(jsonPath("$.currentPage").value(0));
        }

        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void getAllTasks_ShouldReturnFilteredTasks_WhenFilteringByPriority() throws Exception {
            TaskPage taskPage = new TaskPage(tasks.subList(0, 1), 1, 1L, 0);

            when(taskService.getAllFiltered(any(TaskFilterParameters.class))).thenReturn(taskPage);

            mockMvc.perform(get("/tasks")
                            .param("priority", "medium")
                            .param("size", "10")
                            .param("page", "0"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.tasks.length()").value(1))
                    .andExpect(jsonPath("$.tasks[0].title").value("Task 1"))
                    .andExpect(jsonPath("$.tasks[0].priority").value("MEDIUM"))
                    .andExpect(jsonPath("$.totalElements").value(1))
                    .andExpect(jsonPath("$.totalPages").value(1))
                    .andExpect(jsonPath("$.currentPage").value(0));
        }
    }

    @Nested
    @DisplayName("addTask() is working")
    class AddTask {
        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void addTask_ShouldReturnCreatedTask() throws Exception {
            TaskForm form = TaskForm.builder()
                    .title("New Task")
                    .description("New Description")
                    .status("NEW")
                    .priority("MEDIUM")
                    .executorId(UUID.randomUUID().toString())
                    .build();
            TaskDto createdTask = TaskDto.builder()
                    .id(UUID.randomUUID())
                    .title("New Task")
                    .description("New Description")
                    .status("NEW")
                    .priority("MEDIUM")
                    .authorId(UUID.randomUUID())
                    .executorId(UUID.randomUUID())
                    .build();

            when(taskService.save(any(TaskForm.class))).thenReturn(createdTask);

            mockMvc.perform(post("/tasks")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(form)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.title").value("New Task"));
        }

        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void addTask_ShouldReturn400BadRequest_WhenFormIsIncorrect() throws Exception {
            TaskForm form = TaskForm.builder()
                    .description("Description without a title")
                    .status("INVALID_STATUS")
                    .priority("INVALID_PRIORITY")
                    .executorId("invalid-uuid")
                    .build();

            mockMvc.perform(post("/tasks")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(form)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errors.size()").value(4))
                    .andExpect(jsonPath("$.errors[?(@.field=='title')].message")
                            .value("Заголовок задачи не может быть пустым"))
                    .andExpect(jsonPath("$.errors[?(@.field=='status')].message")
                            .value("Недопустимый статус задачи"))
                    .andExpect(jsonPath("$.errors[?(@.field=='priority')].message")
                            .value("Недопустимый приоритет задачи"))
                    .andExpect(jsonPath("$.errors[?(@.field=='executorId')].message")
                            .value("ID исполнителя должен быть указан в формате UUID"));
        }
    }

    @Test
    @WithMockUser(username = "testuser", authorities = "ADMIN")
    void updateTask_ShouldReturnUpdatedTask() throws Exception {
        UUID taskId = UUID.randomUUID();
        TaskForm form = TaskForm.builder()
                .title("Updated Task")
                .description("Updated Description")
                .status("ASSIGNED")
                .priority("HIGH")
                .executorId(UUID.randomUUID().toString())
                .build();
        TaskDto updatedTask = TaskDto.builder()
                .id(taskId)
                .title("Updated Task")
                .description("Updated Description")
                .status("ASSIGNED")
                .priority("HIGH")
                .authorId(UUID.randomUUID())
                .executorId(UUID.randomUUID())
                .build();

        when(taskService.updateById(eq(taskId), any(TaskForm.class))).thenReturn(updatedTask);

        mockMvc.perform(patch("/tasks/" + taskId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(form)))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.title").value("Updated Task"));
    }

    @Test
    @WithMockUser(username = "testuser", authorities = "ADMIN")
    void deleteTask_ShouldReturnAcceptedStatus() throws Exception {
        UUID taskId = UUID.randomUUID();

        mockMvc.perform(delete("/tasks/" + taskId))
                .andExpect(status().isAccepted());

        verify(taskService, times(1)).deleteById(taskId);
    }

    @Nested
    @DisplayName("updateTaskStatus() is working")
    class UpdateTaskStatus {
        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void updateTaskStatus_ShouldReturnUpdatedTaskStatus() throws Exception {
            UUID taskId = UUID.randomUUID();
            TaskStatusForm statusForm = TaskStatusForm.builder()
                    .status("ASSIGNED")
                    .build();
            TaskDto updatedTask = TaskDto.builder()
                    .id(taskId)
                    .title("Task 1")
                    .description("Description 1")
                    .status("ASSIGNED")
                    .priority("MEDIUM")
                    .authorId(UUID.randomUUID())
                    .executorId(UUID.randomUUID())
                    .build();

            when(taskService.updateTaskStatus(eq(taskId), any(TaskStatusForm.class))).thenReturn(updatedTask);

            mockMvc.perform(patch("/tasks/" + taskId + "/status")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(statusForm)))
                    .andExpect(status().isAccepted())
                    .andExpect(jsonPath("$.status").value("ASSIGNED"));
        }

        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void updateTaskStatus_ShouldReturn400BadRequest_WhenStatusIsIncorrect() throws Exception {
            UUID taskId = UUID.randomUUID();
            TaskStatusForm statusForm = TaskStatusForm.builder()
                    .status("INVALID_STATUS")
                    .build();

            mockMvc.perform(patch("/tasks/" + taskId + "/status")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(statusForm)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errors.size()").value(1))
                    .andExpect(jsonPath("$.errors[?(@.field=='status')].message")
                            .value("Недопустимый статус задачи"));
        }
    }

    @Nested
    @DisplayName("getAllAuthorTasks() is working")
    class GetAllAuthorTasks {

        private List<TaskDto> tasks;

        @BeforeEach
        void setUp() {
            tasks = Arrays.asList(
                    TaskDto.builder()
                            .id(UUID.randomUUID())
                            .title("Task 1")
                            .description("Description 1")
                            .status("NEW")
                            .priority("MEDIUM")
                            .authorId(UUID.randomUUID())
                            .executorId(UUID.randomUUID())
                            .build(),
                    TaskDto.builder()
                            .id(UUID.randomUUID())
                            .title("Task 2")
                            .description("Description 2")
                            .status("ASSIGNED")
                            .priority("HIGH")
                            .authorId(UUID.randomUUID())
                            .executorId(UUID.randomUUID())
                            .build()
            );
        }

        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void getAllAuthorTasks_ShouldReturnFilteredTasks_WhenFilteringByAuthorId() throws Exception {
            UUID authorId = UUID.randomUUID();
            TaskFilterParameters filterParameters = TaskFilterParameters.createTaskFilterParameters(null, null, null, null, authorId.toString(), null, 0, 10);
            TaskPage taskPage = new TaskPage(tasks, 1, 2L, 0);

            when(taskService.getAllFiltered(any(TaskFilterParameters.class))).thenReturn(taskPage);

            mockMvc.perform(get("/account/" + authorId + "/tasks/created")
                            .param("size", "10")
                            .param("page", "0"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.tasks.length()").value(2))
                    .andExpect(jsonPath("$.tasks[0].title").value("Task 1"))
                    .andExpect(jsonPath("$.tasks[1].title").value("Task 2"))
                    .andExpect(jsonPath("$.totalElements").value(2))
                    .andExpect(jsonPath("$.totalPages").value(1))
                    .andExpect(jsonPath("$.currentPage").value(0));
        }
    }

    @Nested
    @WithMockUser(username = "testuser", authorities = "ADMIN")
    class GetAllExecutorTasks {

        private List<TaskDto> tasks;

        @BeforeEach
        void setUp() {
            tasks = Arrays.asList(
                    TaskDto.builder()
                            .id(UUID.randomUUID())
                            .title("Task 1")
                            .description("Description 1")
                            .status("NEW")
                            .priority("MEDIUM")
                            .authorId(UUID.randomUUID())
                            .executorId(UUID.randomUUID())
                            .build(),
                    TaskDto.builder()
                            .id(UUID.randomUUID())
                            .title("Task 2")
                            .description("Description 2")
                            .status("ASSIGNED")
                            .priority("HIGH")
                            .authorId(UUID.randomUUID())
                            .executorId(UUID.randomUUID())
                            .build()
            );
        }

        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void getAllExecutorTasks_ShouldReturnFilteredTasks_WhenFilteringByExecutorId() throws Exception {
            UUID executorId = UUID.randomUUID();
            TaskFilterParameters filterParameters = TaskFilterParameters.createTaskFilterParameters(null, null, null, null, null, executorId.toString(), 0, 10);
            TaskPage taskPage = new TaskPage(tasks, 1, 2L, 0);

            when(taskService.getAllFiltered(any(TaskFilterParameters.class))).thenReturn(taskPage);

            mockMvc.perform(get("/account/" + executorId + "/tasks/assigned")
                            .param("size", "10")
                            .param("page", "0"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.tasks.length()").value(2))
                    .andExpect(jsonPath("$.tasks[0].title").value("Task 1"))
                    .andExpect(jsonPath("$.tasks[1].title").value("Task 2"))
                    .andExpect(jsonPath("$.totalElements").value(2))
                    .andExpect(jsonPath("$.totalPages").value(1))
                    .andExpect(jsonPath("$.currentPage").value(0));
        }
    }
}
