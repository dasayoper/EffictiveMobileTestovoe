package by.dasayoper.taskmanager.controller;

import by.dasayoper.taskmanager.dto.CommentDto;
import by.dasayoper.taskmanager.dto.form.CommentForm;
import by.dasayoper.taskmanager.dto.page.CommentPage;
import by.dasayoper.taskmanager.dto.util.CommentFilterParameters;
import by.dasayoper.taskmanager.exception.CommentNotFoundException;
import by.dasayoper.taskmanager.service.CommentService;
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

import java.time.LocalDateTime;
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
public class CommentControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private CommentService commentService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Nested
    @DisplayName("getComment() is working")
    class GetComment {
        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void getComment_ShouldReturnComment_WhenCommentExists() throws Exception {
            UUID commentId = UUID.randomUUID();
            CommentDto comment = CommentDto.builder()
                    .id(commentId)
                    .text("Great work!")
                    .authorId(UUID.randomUUID())
                    .taskId(UUID.randomUUID())
                    .postedAt(LocalDateTime.now())
                    .lastEditedAt(LocalDateTime.now())
                    .build();

            when(commentService.getById(commentId)).thenReturn(comment);

            mockMvc.perform(get("/comments/" + commentId))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(commentId.toString()))
                    .andExpect(jsonPath("$.text").value("Great work!"));
        }

        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void getComment_ShouldReturn404NotFound_WhenCommentDoesNotExist() throws Exception {
            UUID commentId = UUID.randomUUID();

            when(commentService.getById(commentId)).thenThrow(new CommentNotFoundException("Comment not found with id: " + commentId));

            mockMvc.perform(get("/comments/" + commentId))
                    .andExpect(status().isNotFound())
                    .andExpect(jsonPath("$.code").value(404))
                    .andExpect(jsonPath("$.status").value("NOT_FOUND"))
                    .andExpect(jsonPath("$.message").value("Comment not found with id: " + commentId));
        }
    }

    @Nested
    @DisplayName("getAllComments() is working")
    class GetAllComments {

        private List<CommentDto> comments;

        @BeforeEach
        void setUp() {
            comments = Arrays.asList(
                    CommentDto.builder()
                            .id(UUID.randomUUID())
                            .text("Great work!")
                            .authorId(UUID.randomUUID())
                            .taskId(UUID.randomUUID())
                            .postedAt(LocalDateTime.now())
                            .lastEditedAt(LocalDateTime.now())
                            .build(),
                    CommentDto.builder()
                            .id(UUID.randomUUID())
                            .text("Excellent job!")
                            .authorId(UUID.randomUUID())
                            .taskId(UUID.randomUUID())
                            .postedAt(LocalDateTime.now())
                            .lastEditedAt(LocalDateTime.now())
                            .build()
            );
        }

        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void getAllComments_ShouldReturnFilteredComments_WhenFilteringByText() throws Exception {
            CommentFilterParameters filterParameters = CommentFilterParameters.createCommentFilterParameters("Great", null, null, null, null, null, null, null, 0, 10);
            CommentPage commentPage = new CommentPage(comments, 1, 2L, 0);

            when(commentService.getAllFiltered(any(CommentFilterParameters.class))).thenReturn(commentPage);

            mockMvc.perform(get("/comments")
                            .param("text", "Great")
                            .param("size", "10")
                            .param("page", "0"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.comments.length()").value(2))
                    .andExpect(jsonPath("$.comments[0].text").value("Great work!"))
                    .andExpect(jsonPath("$.comments[1].text").value("Excellent job!"))
                    .andExpect(jsonPath("$.totalElements").value(2))
                    .andExpect(jsonPath("$.totalPages").value(1))
                    .andExpect(jsonPath("$.currentPage").value(0));
        }

        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void getAllComments_ShouldReturnFilteredComments_WhenFilteringByLength() throws Exception {
            CommentPage commentPage = new CommentPage(comments.subList(1,2), 1, 1L, 0);

            when(commentService.getAllFiltered(any(CommentFilterParameters.class))).thenReturn(commentPage);

            mockMvc.perform(get("/comments")
                            .param("minLength", "12")
                            .param("size", "10")
                            .param("page", "0"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.comments.length()").value(1))
                    .andExpect(jsonPath("$.comments[0].text").value("Excellent job!"))
                    .andExpect(jsonPath("$.totalElements").value(1))
                    .andExpect(jsonPath("$.totalPages").value(1))
                    .andExpect(jsonPath("$.currentPage").value(0));
        }
    }

    @Nested
    @DisplayName("addComment() is working")
    class AddComment {
        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void addComment_ShouldReturnCreatedComment() throws Exception {
            UUID taskId = UUID.randomUUID();
            CommentForm form = CommentForm.builder()
                    .text("New Comment")
                    .build();
            CommentDto createdComment = CommentDto.builder()
                    .id(UUID.randomUUID())
                    .text("New Comment")
                    .authorId(UUID.randomUUID())
                    .taskId(taskId)
                    .postedAt(LocalDateTime.now())
                    .lastEditedAt(LocalDateTime.now())
                    .build();

            when(commentService.save(eq(taskId), any(CommentForm.class))).thenReturn(createdComment);

            mockMvc.perform(post("/tasks/" + taskId + "/comments")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(form)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.text").value("New Comment"));
        }

        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void addComment_ShouldReturn400BadRequest_WhenFormIsIncorrect() throws Exception {
            UUID taskId = UUID.randomUUID();
            CommentForm form = CommentForm.builder()
                    .text("")
                    .build();

            mockMvc.perform(post("/tasks/" + taskId + "/comments")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(form)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errors.size()").value(1))
                    .andExpect(jsonPath("$.errors[?(@.field=='text')].message")
                            .value("Длина комментария должна быть от 1 до 500 символов"));
        }
    }

    @Test
    @WithMockUser(username = "testuser", authorities = "ADMIN")
    void updateComment_ShouldReturnUpdatedComment() throws Exception {
        UUID commentId = UUID.randomUUID();
        CommentForm form = CommentForm.builder()
                .text("Updated Comment")
                .build();
        CommentDto updatedComment = CommentDto.builder()
                .id(commentId)
                .text("Updated Comment")
                .authorId(UUID.randomUUID())
                .taskId(UUID.randomUUID())
                .postedAt(LocalDateTime.now())
                .lastEditedAt(LocalDateTime.now())
                .build();

        when(commentService.updateById(eq(commentId), any(CommentForm.class))).thenReturn(updatedComment);

        mockMvc.perform(patch("/comments/" + commentId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(form)))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.text").value("Updated Comment"));
    }

    @Test
    @WithMockUser(username = "testuser", authorities = "ADMIN")
    void deleteComment_ShouldReturnAcceptedStatus() throws Exception {
        UUID commentId = UUID.randomUUID();

        mockMvc.perform(delete("/comments/" + commentId))
                .andExpect(status().isAccepted());

        verify(commentService, times(1)).deleteById(commentId);
    }

    @Nested
    @DisplayName("getAllTaskComments() is working")
    class GetAllTaskComments {

        private List<CommentDto> comments;

        @BeforeEach
        void setUp() {
            comments = Arrays.asList(
                    CommentDto.builder()
                            .id(UUID.randomUUID())
                            .text("Great work!")
                            .authorId(UUID.randomUUID())
                            .taskId(UUID.randomUUID())
                            .postedAt(LocalDateTime.now())
                            .lastEditedAt(LocalDateTime.now())
                            .build(),
                    CommentDto.builder()
                            .id(UUID.randomUUID())
                            .text("Excellent job!")
                            .authorId(UUID.randomUUID())
                            .taskId(UUID.randomUUID())
                            .postedAt(LocalDateTime.now())
                            .lastEditedAt(LocalDateTime.now())
                            .build()
            );
        }

        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void getAllTaskComments_ShouldReturnFilteredComments_WhenFilteringByTaskId() throws Exception {
            UUID taskId = UUID.randomUUID();
            CommentFilterParameters filterParameters = CommentFilterParameters.createCommentFilterParameters(null, null, taskId.toString(), null, null, null, null, null, 0, 10);
            CommentPage commentPage = new CommentPage(comments, 1, 2L, 0);

            when(commentService.getAllFiltered(any(CommentFilterParameters.class))).thenReturn(commentPage);

            mockMvc.perform(get("/tasks/" + taskId + "/comments")
                            .param("size", "10")
                            .param("page", "0"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.comments.length()").value(2))
                    .andExpect(jsonPath("$.comments[0].text").value("Great work!"))
                    .andExpect(jsonPath("$.comments[1].text").value("Excellent job!"))
                    .andExpect(jsonPath("$.totalElements").value(2))
                    .andExpect(jsonPath("$.totalPages").value(1))
                    .andExpect(jsonPath("$.currentPage").value(0));
        }
    }

    @Nested
    @DisplayName("getAllAccountComments() is working")
    class GetAllAccountComments {

        private List<CommentDto> comments;

        @BeforeEach
        void setUp() {
            comments = Arrays.asList(
                    CommentDto.builder()
                            .id(UUID.randomUUID())
                            .text("Great work!")
                            .authorId(UUID.randomUUID())
                            .taskId(UUID.randomUUID())
                            .postedAt(LocalDateTime.now())
                            .lastEditedAt(LocalDateTime.now())
                            .build(),
                    CommentDto.builder()
                            .id(UUID.randomUUID())
                            .text("Excellent job!")
                            .authorId(UUID.randomUUID())
                            .taskId(UUID.randomUUID())
                            .postedAt(LocalDateTime.now())
                            .lastEditedAt(LocalDateTime.now())
                            .build()
            );
        }

        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void getAllAccountComments_ShouldReturnFilteredComments_WhenFilteringByAuthorId() throws Exception {
            UUID authorId = UUID.randomUUID();
            CommentFilterParameters filterParameters = CommentFilterParameters.createCommentFilterParameters(null, authorId.toString(), null, null, null, null, null, null, 0, 10);
            CommentPage commentPage = new CommentPage(comments, 1, 2L, 0);

            when(commentService.getAllFiltered(any(CommentFilterParameters.class))).thenReturn(commentPage);

            mockMvc.perform(get("/accounts/" + authorId + "/comments")
                            .param("size", "10")
                            .param("page", "0"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.comments.length()").value(2))
                    .andExpect(jsonPath("$.comments[0].text").value("Great work!"))
                    .andExpect(jsonPath("$.comments[1].text").value("Excellent job!"))
                    .andExpect(jsonPath("$.totalElements").value(2))
                    .andExpect(jsonPath("$.totalPages").value(1))
                    .andExpect(jsonPath("$.currentPage").value(0));
        }
    }
}

