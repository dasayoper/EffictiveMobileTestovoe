package by.dasayoper.taskmanager.service.impl;

import by.dasayoper.taskmanager.dto.CommentDto;
import by.dasayoper.taskmanager.dto.form.CommentForm;
import by.dasayoper.taskmanager.dto.page.CommentPage;
import by.dasayoper.taskmanager.dto.util.CommentFilterParameters;
import by.dasayoper.taskmanager.exception.CommentNotFoundException;
import by.dasayoper.taskmanager.exception.TaskNotFoundException;
import by.dasayoper.taskmanager.model.Account;
import by.dasayoper.taskmanager.model.BaseEntity;
import by.dasayoper.taskmanager.model.Comment;
import by.dasayoper.taskmanager.model.Task;
import by.dasayoper.taskmanager.repository.CommentRepository;
import by.dasayoper.taskmanager.repository.TaskRepository;
import by.dasayoper.taskmanager.service.CommentService;
import by.dasayoper.taskmanager.service.SecurityService;
import by.dasayoper.taskmanager.specification.CommentSpecification;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.UUID;

import static by.dasayoper.taskmanager.dto.CommentDto.from;

@Service
@RequiredArgsConstructor
public class CommentServiceImpl implements CommentService {

    private final CommentRepository commentRepository;
    private final SecurityService securityService;
    private final TaskRepository taskRepository;

    private final Logger LOGGER = LoggerFactory.getLogger(this.getClass());

    /**
     * Получение комментария по идентификатору.
     *
     * @param id уникальный идентификатор комментария.
     * @return объект {@link CommentDto}, содержащий данные комментария.
     * @throws CommentNotFoundException если комментарий с указанным id не найден.
     */
    @Override
    public CommentDto getById(UUID id) {
        LOGGER.info("Попытка получения комментария с id: {}", id);
        Comment comment = findCommentById(id);
        LOGGER.info("Комментарий с id: {} успешно найден", id);
        return from(comment);
    }

    /**
     * Получение списка всех комментариев.
     *
     * @return список всех комментариев в виде {@link CommentDto}.
     */
    @Override
    public List<CommentDto> getAll() {
        LOGGER.info("Запрос на получение всех комментариев");
        List<CommentDto> comments = from(commentRepository.findAll());
        LOGGER.info("Получено {} комментариев", comments.size());
        return comments;
    }

    /**
     * Получение комментариев с фильтрацией и пагинацией.
     *
     * @param filterParameters параметры фильтрации комментариев {@link CommentFilterParameters}.
     * @return объект {@link CommentPage}, содержащий список комментариев в виде {@link CommentDto} и данные о пагинации.
     */
    @Override
    public CommentPage getAllFiltered(CommentFilterParameters filterParameters) {
        LOGGER.info("Запрос на получение комментариев с фильтрацией по параметрам: {}", filterParameters);
        Specification<Comment> specification = buildCommentSpecification(filterParameters);

        Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
        Page<Comment> commentPage = commentRepository.findAll(specification, pageable);

        LOGGER.info("Найдено {} комментариев, всего страниц: {}, элементов: {}",
                commentPage.getContent().size(),
                commentPage.getTotalPages(),
                commentPage.getTotalElements());

        return CommentPage.builder()
                .comments(from(commentPage.getContent()))
                .totalPages(commentPage.getTotalPages())
                .totalElements(commentPage.getTotalElements())
                .currentPage(pageable.getPageNumber())
                .build();
    }

    /**
     * Добавление нового комментария к задаче.
     *
     * @param taskId уникальный идентификатор задачи.
     * @param form   данные для создания комментария.
     * @return объект {@link CommentDto}, содержащий данные сохраненного комментария.
     * @throws AccessDeniedException если пользователь не является исполнителем задачи или администратором.
     */
    @Override
    public CommentDto save(UUID taskId, CommentForm form) {
        LOGGER.info("Попытка добавления комментария к задаче с id: {}", taskId);
        Task task = findTaskById(taskId);

        Account authorizedAccount = securityService.getAuthorizedAccount();

        if (task.getExecutor().equals(authorizedAccount) || authorizedAccount.getRole().equals(Account.Role.ADMIN)) {

            Comment newComment = Comment.builder()
                    .text(form.getText())
                    .author(securityService.getAuthorizedAccount())
                    .task(task)
                    .postedAt(LocalDateTime.now())
                    .lastEditedAt(LocalDateTime.now())
                    .state(BaseEntity.State.ACTIVE)
                    .build();

            CommentDto savedComment = from(commentRepository.save(newComment));
            LOGGER.info("Комментарий успешно добавлен к задаче с id: {}", taskId);
            return savedComment;
        } else {
            LOGGER.warn("Недостаточно прав для добавления комментария к задаче c id: {}", taskId);
            throw new AccessDeniedException("Вы не являетесь исполнителем задачи или администратором");
        }
    }

    /**
     * Обновление комментария по идентификатору.
     *
     * @param id          уникальный идентификатор комментария.
     * @param commentForm данные для обновления комментария {@link CommentForm}.
     * @return объект {@link CommentDto}, содержащий данные обновленного комментария.
     * @throws CommentNotFoundException если комментарий с указанным id не найден.
     * @throws AccessDeniedException    если пользователь не является автором комментария или администратором.
     */
    @Override
    public CommentDto updateById(UUID id, CommentForm commentForm) {
        LOGGER.info("Запрос на обновление комментария с id: {}", id);
        Account authorizedAccount = securityService.getAuthorizedAccount();

        Comment comment = findCommentById(id);

        if (comment.getAuthor().equals(authorizedAccount) || authorizedAccount.getRole().equals(Account.Role.ADMIN)) {

            comment.setText(commentForm.getText());
            comment.setLastEditedAt(LocalDateTime.now());

            CommentDto updatedComment = from(commentRepository.save(comment));
            LOGGER.info("Комментарий с id: {} успешно обновлен", id);
            return updatedComment;
        } else {
            LOGGER.warn("Недостаточно прав для обновления комментария c id: {}", id);
            throw new AccessDeniedException("Вы не являетесь автором комментария или администратором");
        }
    }

    /**
     * Удаление комментария по идентификатору.
     *
     * @param id уникальный идентификатор комментария.
     * @throws CommentNotFoundException если комментарий с указанным id не найден.
     * @throws AccessDeniedException    если пользователь не является автором комментария или администратором.
     */
    @Override
    public void deleteById(UUID id) {
        LOGGER.info("Запрос на удаление комментария с id: {}", id);
        Account authorizedAccount = securityService.getAuthorizedAccount();

        Comment comment = findCommentById(id);

        if (comment.getAuthor().equals(authorizedAccount) || authorizedAccount.getRole().equals(Account.Role.ADMIN)) {
            comment.setState(BaseEntity.State.DELETED);

            commentRepository.save(comment);
            LOGGER.info("State комментария с id: {} изменен на 'DELETED'", id);
        } else {
            LOGGER.warn("Недостаточно прав для удаления комментария c id: {}", id);
            throw new AccessDeniedException("Вы не являетесь автором комментария или администратором");
        }
    }

    /**
     * Вспомогательный метод для поиска комментария по идентификатору.
     *
     * @param id уникальный идентификатор комментария.
     * @return найденный объект {@link Comment}.
     * @throws CommentNotFoundException если комментарий с указанным id не найден.
     */
    private Comment findCommentById(UUID id) {
        LOGGER.debug("Попытка получения комментария с id: {}", id);
        return commentRepository.findById(id)
                .orElseThrow(() -> {
                    LOGGER.error("Комментарий с id: {} не найден", id);
                    return new CommentNotFoundException("Комментарий с id: " + id + " не найден");
                });
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
     * Вспомогательный метод для создания спецификации для фильтрации комментариев.
     *
     * @param filterParameters параметры фильтрации комментариев {@link CommentFilterParameters}.
     * @return объект {@link Specification<Comment>} для поиска.
     */
    private Specification<Comment> buildCommentSpecification(CommentFilterParameters filterParameters) {
        LOGGER.debug("Создание спецификации для фильтрации: {}", filterParameters);

        Specification<Comment> specification = Specification.where(CommentSpecification.notDeleted());

        if (filterParameters.getText() != null && !filterParameters.getText().isBlank()) {
            specification = specification.and(CommentSpecification.textContains(filterParameters.getText()));
        }

        if (filterParameters.getAuthorId() != null && !filterParameters.getAuthorId().isBlank()) {
            try {
                UUID authorId = UUID.fromString(filterParameters.getAuthorId());
                specification = specification.and(CommentSpecification.hasAuthor(authorId));
            } catch (NumberFormatException e) {
                LOGGER.warn("Неверный формат authorId в фильтре: {}", filterParameters.getAuthorId());
            }
        }

        if (filterParameters.getTaskId() != null && !filterParameters.getTaskId().isBlank()) {
            try {
                UUID taskId = UUID.fromString(filterParameters.getTaskId());
                specification = specification.and(CommentSpecification.hasTask(taskId));
            } catch (NumberFormatException e) {
                LOGGER.warn("Неверный формат taskId в фильтре: {}", filterParameters.getTaskId());
            }
        }

        if (filterParameters.getStartDate() != null && !filterParameters.getStartDate().isBlank()) {
            try {
                LocalDateTime startDate = LocalDateTime.parse(filterParameters.getStartDate());
                specification = specification.and(CommentSpecification.startDate(startDate));
            } catch (DateTimeParseException e) {
                LOGGER.warn("Неверный формат startDate в фильтре: {}", filterParameters.getStartDate());
            }
        }

        if (filterParameters.getEndDate() != null && !filterParameters.getEndDate().isBlank()) {
            try {
                LocalDateTime endDate = LocalDateTime.parse(filterParameters.getEndDate());
                specification = specification.and(CommentSpecification.endDate(endDate));
            } catch (DateTimeParseException e) {
                LOGGER.warn("Неверный формат endDate в фильтре: {}", filterParameters.getEndDate());
            }
        }

        if (filterParameters.getWasEdited() != null && !filterParameters.getWasEdited().isBlank()) {
            try {
                Boolean wasEdited = Boolean.parseBoolean(filterParameters.getWasEdited());
                specification = specification.and(CommentSpecification.wasEdited(wasEdited));
            } catch (IllegalArgumentException e) {
                LOGGER.warn("Неверное значение wasEdited в фильтре: {}", filterParameters.getWasEdited());
            }
        }

        if (filterParameters.getMinLength() != null && !filterParameters.getMinLength().isBlank()) {
            try {
                int minLength = Integer.parseInt(filterParameters.getMinLength());
                specification = specification.and(CommentSpecification.minLength(minLength));
            } catch (NumberFormatException e) {
                LOGGER.warn("Неверный формат minLength в фильтре: {}", filterParameters.getMinLength());
            }
        }


        if (filterParameters.getMaxLength() != null && !filterParameters.getMaxLength().isBlank()) {
            try {
                int maxLength = Integer.parseInt(filterParameters.getMaxLength());
                specification = specification.and(CommentSpecification.maxLength(maxLength));
            } catch (NumberFormatException e) {
                LOGGER.warn("Неверный формат maxLength в фильтре: {}", filterParameters.getMaxLength());
            }
        }

        LOGGER.debug("Спецификация создана");
        return specification;
    }
}
