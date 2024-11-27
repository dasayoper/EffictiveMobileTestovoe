package by.dasayoper.taskmanager.service;

import by.dasayoper.taskmanager.dto.CommentDto;
import by.dasayoper.taskmanager.dto.form.CommentForm;
import by.dasayoper.taskmanager.dto.page.CommentPage;
import by.dasayoper.taskmanager.dto.util.CommentFilterParameters;
import by.dasayoper.taskmanager.exception.CommentNotFoundException;
import by.dasayoper.taskmanager.model.Account;
import by.dasayoper.taskmanager.model.BaseEntity;
import by.dasayoper.taskmanager.model.Comment;
import by.dasayoper.taskmanager.model.Task;
import by.dasayoper.taskmanager.repository.CommentRepository;
import by.dasayoper.taskmanager.repository.TaskRepository;
import by.dasayoper.taskmanager.service.impl.CommentServiceImpl;
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

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

public class CommentServiceImplTest {

    @Mock
    private CommentRepository commentRepository;

    @Mock
    private SecurityService securityService;

    @Mock
    private TaskRepository taskRepository;

    @InjectMocks
    private CommentServiceImpl commentService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Nested
    @DisplayName("getById() is working")
    class GetByIdTest {
        @Test
        void getById_shouldReturnComment_whenCommentExists() {
            UUID commentId = UUID.randomUUID();
            Comment comment = Comment.builder()
                    .id(commentId)
                    .text("Great work!")
                    .author(Account.builder().id(UUID.randomUUID()).build())
                    .task(Task.builder().id(UUID.randomUUID()).build())
                    .postedAt(LocalDateTime.now())
                    .lastEditedAt(LocalDateTime.now())
                    .state(BaseEntity.State.ACTIVE)
                    .build();

            when(commentRepository.findById(commentId)).thenReturn(Optional.of(comment));

            CommentDto commentDto = commentService.getById(commentId);

            assertNotNull(commentDto);
            assertEquals("Great work!", commentDto.getText());
        }

        @Test
        void getById_shouldThrowException_whenCommentDoesNotExist() {
            UUID commentId = UUID.randomUUID();

            when(commentRepository.findById(commentId)).thenReturn(Optional.empty());

            assertThrows(CommentNotFoundException.class, () -> commentService.getById(commentId));
        }
    }

    @Test
    void getAll_shouldReturnAllComments() {
        List<Comment> comments = List.of(
                Comment.builder()
                        .id(UUID.randomUUID())
                        .text("Great work!")
                        .author(Account.builder().id(UUID.randomUUID()).build())
                        .task(Task.builder().id(UUID.randomUUID()).build())
                        .postedAt(LocalDateTime.now())
                        .lastEditedAt(LocalDateTime.now())
                        .state(BaseEntity.State.ACTIVE)
                        .build(),
                Comment.builder()
                        .id(UUID.randomUUID())
                        .text("Excellent job!")
                        .author(Account.builder().id(UUID.randomUUID()).build())
                        .task(Task.builder().id(UUID.randomUUID()).build())
                        .postedAt(LocalDateTime.now())
                        .lastEditedAt(LocalDateTime.now())
                        .state(BaseEntity.State.ACTIVE)
                        .build()
        );

        when(commentRepository.findAll()).thenReturn(comments);

        List<CommentDto> commentDtoList = commentService.getAll();

        assertNotNull(commentDtoList);
        assertEquals(2, commentDtoList.size());

        CommentDto firstCommentDto = commentDtoList.get(0);
        assertEquals("Great work!", firstCommentDto.getText());

        CommentDto secondCommentDto = commentDtoList.get(1);
        assertEquals("Excellent job!", secondCommentDto.getText());
    }

    @Nested
    @DisplayName("getAllFiltered() is working")
    class GetAllFilteredTests {

        @Test
        void getAllFiltered_shouldReturnAllComments_WhenNoFiltersApplied() {
            List<Comment> comments = List.of(
                    Comment.builder()
                            .id(UUID.randomUUID())
                            .text("Great work!")
                            .author(Account.builder().id(UUID.randomUUID()).build())
                            .task(Task.builder().id(UUID.randomUUID()).build())
                            .postedAt(LocalDateTime.now())
                            .lastEditedAt(LocalDateTime.now())
                            .state(BaseEntity.State.ACTIVE)
                            .build(),
                    Comment.builder()
                            .id(UUID.randomUUID())
                            .text("Excellent job!")
                            .author(Account.builder().id(UUID.randomUUID()).build())
                            .task(Task.builder().id(UUID.randomUUID()).build())
                            .postedAt(LocalDateTime.now())
                            .lastEditedAt(LocalDateTime.now())
                            .state(BaseEntity.State.ACTIVE)
                            .build()
            );

            CommentFilterParameters filterParameters = CommentFilterParameters.createCommentFilterParameters(null, null, null, null, null, null, null, null, 0, 10);

            Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
            Page<Comment> commentPage = new PageImpl<>(comments, pageable, comments.size());
            when(commentRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(commentPage);

            CommentPage result = commentService.getAllFiltered(filterParameters);

            assertNotNull(result);
            assertEquals(2, result.getComments().size());
            assertEquals(1, result.getTotalPages());
        }

        @Test
        void getAllFiltered_shouldFilterComments_ByText() {
            List<Comment> comments = List.of(
                    Comment.builder()
                            .id(UUID.randomUUID())
                            .text("Filtered Comment")
                            .author(Account.builder().id(UUID.randomUUID()).build())
                            .task(Task.builder().id(UUID.randomUUID()).build())
                            .postedAt(LocalDateTime.now())
                            .lastEditedAt(LocalDateTime.now())
                            .state(BaseEntity.State.ACTIVE)
                            .build()
            );

            CommentFilterParameters filterParameters = CommentFilterParameters.createCommentFilterParameters("Filt", null, null, null, null, null, null, null, 0, 10);

            Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
            Page<Comment> commentPage = new PageImpl<>(comments, pageable, comments.size());
            when(commentRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(commentPage);

            CommentPage result = commentService.getAllFiltered(filterParameters);

            assertNotNull(result);
            assertEquals(1, result.getComments().size());
            assertEquals("Filtered Comment", result.getComments().get(0).getText());
        }

        @Test
        void getAllFiltered_shouldFilterComments_ByAuthorId() {
            UUID authorId = UUID.randomUUID();
            List<Comment> comments = List.of(
                    Comment.builder()
                            .id(UUID.randomUUID())
                            .text("Great work!")
                            .author(Account.builder().id(authorId).build())
                            .task(Task.builder().id(UUID.randomUUID()).build())
                            .postedAt(LocalDateTime.now())
                            .lastEditedAt(LocalDateTime.now())
                            .state(BaseEntity.State.ACTIVE)
                            .build()
            );

            CommentFilterParameters filterParameters = CommentFilterParameters.createCommentFilterParameters(null, authorId.toString(), null, null, null, null, null, null, 0, 10);

            Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
            Page<Comment> commentPage = new PageImpl<>(comments, pageable, comments.size());
            when(commentRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(commentPage);

            CommentPage result = commentService.getAllFiltered(filterParameters);

            assertNotNull(result);
            assertEquals(1, result.getComments().size());
            assertEquals(authorId, result.getComments().get(0).getAuthorId());
        }

        @Test
        void getAllFiltered_shouldFilterComments_ByTaskId() {
            UUID taskId = UUID.randomUUID();
            List<Comment> comments = List.of(
                    Comment.builder()
                            .id(UUID.randomUUID())
                            .text("Great work!")
                            .author(Account.builder().id(UUID.randomUUID()).build())
                            .task(Task.builder().id(taskId).build())
                            .postedAt(LocalDateTime.now())
                            .lastEditedAt(LocalDateTime.now())
                            .state(BaseEntity.State.ACTIVE)
                            .build()
            );

            CommentFilterParameters filterParameters = CommentFilterParameters.createCommentFilterParameters(null, null, taskId.toString(), null, null, null, null, null, 0, 10);

            Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
            Page<Comment> commentPage = new PageImpl<>(comments, pageable, comments.size());
            when(commentRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(commentPage);

            CommentPage result = commentService.getAllFiltered(filterParameters);

            assertNotNull(result);
            assertEquals(1, result.getComments().size());
            assertEquals(taskId, result.getComments().get(0).getTaskId());
        }

        @Test
        void getAllFiltered_shouldFilterComments_ByStartDate() {
            LocalDateTime startDate = LocalDateTime.now().minusDays(1);
            List<Comment> comments = List.of(
                    Comment.builder()
                            .id(UUID.randomUUID())
                            .text("Great work!")
                            .author(Account.builder().id(UUID.randomUUID()).build())
                            .task(Task.builder().id(UUID.randomUUID()).build())
                            .postedAt(startDate)
                            .lastEditedAt(LocalDateTime.now())
                            .state(BaseEntity.State.ACTIVE)
                            .build()
            );

            CommentFilterParameters filterParameters = CommentFilterParameters.createCommentFilterParameters(null, null, null, startDate.toString(), null, null, null, null, 0, 10);

            Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
            Page<Comment> commentPage = new PageImpl<>(comments, pageable, comments.size());
            when(commentRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(commentPage);

            CommentPage result = commentService.getAllFiltered(filterParameters);

            assertNotNull(result);
            assertEquals(1, result.getComments().size());
            assertEquals(startDate, result.getComments().get(0).getPostedAt());
        }

        @Test
        void getAllFiltered_shouldFilterComments_ByEndDate() {
            LocalDateTime endDate = LocalDateTime.now().plusDays(1);
            List<Comment> comments = List.of(
                    Comment.builder()
                            .id(UUID.randomUUID())
                            .text("Great work!")
                            .author(Account.builder().id(UUID.randomUUID()).build())
                            .task(Task.builder().id(UUID.randomUUID()).build())
                            .postedAt(LocalDateTime.now())
                            .lastEditedAt(endDate)
                            .state(BaseEntity.State.ACTIVE)
                            .build()
            );

            CommentFilterParameters filterParameters = CommentFilterParameters.createCommentFilterParameters(null, null, null, null, endDate.toString(), null, null, null, 0, 10);

            Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
            Page<Comment> commentPage = new PageImpl<>(comments, pageable, comments.size());
            when(commentRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(commentPage);

            CommentPage result = commentService.getAllFiltered(filterParameters);

            assertNotNull(result);
            assertEquals(1, result.getComments().size());
            assertEquals(endDate, result.getComments().get(0).getLastEditedAt());
        }

        @Test
        void getAllFiltered_shouldFilterComments_ByWasEdited() {
            List<Comment> comments = List.of(
                    Comment.builder()
                            .id(UUID.randomUUID())
                            .text("Great work!")
                            .author(Account.builder().id(UUID.randomUUID()).build())
                            .task(Task.builder().id(UUID.randomUUID()).build())
                            .postedAt(LocalDateTime.now())
                            .lastEditedAt(LocalDateTime.now())
                            .state(BaseEntity.State.ACTIVE)
                            .build()
            );

            CommentFilterParameters filterParameters = CommentFilterParameters.createCommentFilterParameters(null, null, null, null, null, "true", null, null, 0, 10);

            Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
            Page<Comment> commentPage = new PageImpl<>(comments, pageable, comments.size());
            when(commentRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(commentPage);

            CommentPage result = commentService.getAllFiltered(filterParameters);

            assertNotNull(result);
            assertEquals(1, result.getComments().size());
            assertNotNull(result.getComments().get(0).getLastEditedAt());
        }

        @Test
        void getAllFiltered_shouldFilterComments_ByMinLength() {
            List<Comment> comments = List.of(
                    Comment.builder()
                            .id(UUID.randomUUID())
                            .text("Great work!")
                            .author(Account.builder().id(UUID.randomUUID()).build())
                            .task(Task.builder().id(UUID.randomUUID()).build())
                            .postedAt(LocalDateTime.now())
                            .lastEditedAt(LocalDateTime.now())
                            .state(BaseEntity.State.ACTIVE)
                            .build()
            );

            CommentFilterParameters filterParameters = CommentFilterParameters.createCommentFilterParameters(null, null, null, null, null, null, "10", null, 0, 10);

            Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
            Page<Comment> commentPage = new PageImpl<>(comments, pageable, comments.size());
            when(commentRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(commentPage);

            CommentPage result = commentService.getAllFiltered(filterParameters);

            assertNotNull(result);
            assertEquals(1, result.getComments().size());
            assertTrue(result.getComments().get(0).getText().length() >= 10);
        }

        @Test
        void getAllFiltered_shouldFilterComments_ByMaxLength() {
            List<Comment> comments = List.of(
                    Comment.builder()
                            .id(UUID.randomUUID())
                            .text("Great work!")
                            .author(Account.builder().id(UUID.randomUUID()).build())
                            .task(Task.builder().id(UUID.randomUUID()).build())
                            .postedAt(LocalDateTime.now())
                            .lastEditedAt(LocalDateTime.now())
                            .state(BaseEntity.State.ACTIVE)
                            .build()
            );

            CommentFilterParameters filterParameters = CommentFilterParameters.createCommentFilterParameters(null, null, null, null, null, null, null, "20", 0, 10);

            Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
            Page<Comment> commentPage = new PageImpl<>(comments, pageable, comments.size());
            when(commentRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(commentPage);

            CommentPage result = commentService.getAllFiltered(filterParameters);

            assertNotNull(result);
            assertEquals(1, result.getComments().size());
            assertTrue(result.getComments().get(0).getText().length() <= 20);
        }
    }

    @Nested
    @DisplayName("save() is working")
    class SaveTest {
        @Test
        void save_shouldSaveComment_whenUserIsExecutorOrAdmin() {
            UUID taskId = UUID.randomUUID();
            CommentForm form = CommentForm.builder()
                    .text("New Comment")
                    .build();

            Task task = Task.builder()
                    .id(taskId)
                    .executor(Account.builder().id(UUID.randomUUID()).build())
                    .build();

            Account authorizedAccount = Account.builder()
                    .id(task.getExecutor().getId())
                    .role(Account.Role.ADMIN)
                    .build();

            Comment newComment = Comment.builder()
                    .text(form.getText())
                    .author(authorizedAccount)
                    .task(task)
                    .postedAt(LocalDateTime.now())
                    .lastEditedAt(LocalDateTime.now())
                    .state(BaseEntity.State.ACTIVE)
                    .build();

            when(taskRepository.findById(taskId)).thenReturn(Optional.of(task));
            when(securityService.getAuthorizedAccount()).thenReturn(authorizedAccount);
            when(commentRepository.save(any(Comment.class))).thenReturn(newComment);

            CommentDto savedComment = commentService.save(taskId, form);

            assertNotNull(savedComment);
            assertEquals("New Comment", savedComment.getText());
        }

        @Test
        void save_shouldThrowException_whenUserIsNotExecutorOrAdmin() {
            UUID taskId = UUID.randomUUID();
            CommentForm form = CommentForm.builder()
                    .text("New Comment")
                    .build();

            Task task = Task.builder()
                    .id(taskId)
                    .executor(Account.builder().id(UUID.randomUUID()).build())
                    .build();

            Account authorizedAccount = Account.builder()
                    .id(UUID.randomUUID())
                    .role(Account.Role.COMMON_USER)
                    .build();

            when(taskRepository.findById(taskId)).thenReturn(Optional.of(task));
            when(securityService.getAuthorizedAccount()).thenReturn(authorizedAccount);

            assertThrows(AccessDeniedException.class, () -> commentService.save(taskId, form));
        }
    }

    @Nested
    @DisplayName("updateById() is working")
    class UpdateByIdTest {
        @Test
        void updateById_shouldUpdateComment_whenCommentExistsAndUserIsAuthorOrAdmin() {
            UUID commentId = UUID.randomUUID();
            CommentForm form = CommentForm.builder()
                    .text("Updated Comment")
                    .build();

            Comment comment = Comment.builder()
                    .id(commentId)
                    .text("Old Comment")
                    .author(Account.builder().id(UUID.randomUUID()).build())
                    .task(Task.builder().id(UUID.randomUUID()).build())
                    .postedAt(LocalDateTime.now())
                    .lastEditedAt(LocalDateTime.now())
                    .state(BaseEntity.State.ACTIVE)
                    .build();

            Account authorizedAccount = Account.builder()
                    .id(comment.getAuthor().getId())
                    .role(Account.Role.ADMIN)
                    .build();

            when(commentRepository.findById(commentId)).thenReturn(Optional.of(comment));
            when(securityService.getAuthorizedAccount()).thenReturn(authorizedAccount);
            when(commentRepository.save(any(Comment.class))).thenReturn(comment);

            CommentDto updatedComment = commentService.updateById(commentId, form);

            assertNotNull(updatedComment);
            assertEquals("Updated Comment", updatedComment.getText());
        }

        @Test
        void updateById_shouldThrowException_whenCommentDoesNotExist() {
            UUID commentId = UUID.randomUUID();
            CommentForm form = CommentForm.builder()
                    .text("Updated Comment")
                    .build();

            when(commentRepository.findById(commentId)).thenReturn(Optional.empty());

            assertThrows(CommentNotFoundException.class, () -> commentService.updateById(commentId, form));
        }

        @Test
        void updateById_shouldThrowException_whenUserIsNotAuthorOrAdmin() {
            UUID commentId = UUID.randomUUID();
            CommentForm form = CommentForm.builder()
                    .text("Updated Comment")
                    .build();

            Comment comment = Comment.builder()
                    .id(commentId)
                    .text("Old Comment")
                    .author(Account.builder().id(UUID.randomUUID()).build())
                    .task(Task.builder().id(UUID.randomUUID()).build())
                    .postedAt(LocalDateTime.now())
                    .lastEditedAt(LocalDateTime.now())
                    .state(BaseEntity.State.ACTIVE)
                    .build();

            Account authorizedAccount = Account.builder()
                    .id(UUID.randomUUID())
                    .role(Account.Role.COMMON_USER)
                    .build();

            when(commentRepository.findById(commentId)).thenReturn(Optional.of(comment));
            when(securityService.getAuthorizedAccount()).thenReturn(authorizedAccount);

            assertThrows(AccessDeniedException.class, () -> commentService.updateById(commentId, form));
        }
    }

    @Nested
    @DisplayName("deleteById() is working")
    class DeleteByIdTest {
        @Test
        void deleteById_shouldDeleteComment_whenCommentExistsAndUserIsAuthorOrAdmin() {
            UUID commentId = UUID.randomUUID();
            Comment comment = Comment.builder()
                    .id(commentId)
                    .text("Old Comment")
                    .author(Account.builder().id(UUID.randomUUID()).build())
                    .task(Task.builder().id(UUID.randomUUID()).build())
                    .postedAt(LocalDateTime.now())
                    .lastEditedAt(LocalDateTime.now())
                    .state(BaseEntity.State.ACTIVE)
                    .build();

            Account authorizedAccount = Account.builder()
                    .id(comment.getAuthor().getId())
                    .role(Account.Role.ADMIN)
                    .build();

            when(commentRepository.findById(commentId)).thenReturn(Optional.of(comment));
            when(securityService.getAuthorizedAccount()).thenReturn(authorizedAccount);
            when(commentRepository.save(any(Comment.class))).thenReturn(comment);

            commentService.deleteById(commentId);

            assertEquals(BaseEntity.State.DELETED, comment.getState());
        }

        @Test
        void deleteById_shouldThrowException_whenCommentDoesNotExist() {
            UUID commentId = UUID.randomUUID();

            when(commentRepository.findById(commentId)).thenReturn(Optional.empty());

            assertThrows(CommentNotFoundException.class, () -> commentService.deleteById(commentId));
        }

        @Test
        void deleteById_shouldThrowException_whenUserIsNotAuthorOrAdmin() {
            UUID commentId = UUID.randomUUID();
            Comment comment = Comment.builder()
                    .id(commentId)
                    .text("Old Comment")
                    .author(Account.builder().id(UUID.randomUUID()).build())
                    .task(Task.builder().id(UUID.randomUUID()).build())
                    .postedAt(LocalDateTime.now())
                    .lastEditedAt(LocalDateTime.now())
                    .state(BaseEntity.State.ACTIVE)
                    .build();

            Account authorizedAccount = Account.builder()
                    .id(UUID.randomUUID())
                    .role(Account.Role.COMMON_USER)
                    .build();

            when(commentRepository.findById(commentId)).thenReturn(Optional.of(comment));
            when(securityService.getAuthorizedAccount()).thenReturn(authorizedAccount);

            assertThrows(AccessDeniedException.class, () -> commentService.deleteById(commentId));
        }
    }
}

