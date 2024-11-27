package by.dasayoper.taskmanager.model;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.time.LocalDateTime;

/**
 * Сущность для комментариев к задачам.
 * Представляет собой комментарии, оставленные пользователями на задачу.
 * Каждому комментарию присваивается уникальный идентификатор {@link BaseEntity#id} и состояние {@link BaseEntity#state}.
 * Также, для каждого комментария хранятся:
 * <ul>
 *     <li>Текст комментария {@link #text}.</li>
 *     <li>Автор комментария {@link #author}.</li>
 *     <li>Задача {@link #task}, к которой относится данный комментарий.</li>
 *     <li>Время публикации комментария {@link #postedAt}.</li>
 *     <li>Время последнего редактирования комментария {@link #lastEditedAt}.</li>
 * </ul>
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@SuperBuilder
@ToString
@Entity
@Table(name = "comment")
public class Comment extends BaseEntity {
    private String text;

    /**
     * Автор комментария.
     * Связь с {@link Account}, который оставил комментарий.
     * Каждый комментарий должен быть связан с определенным пользователем.
     */
    @ManyToOne
    @JoinColumn(name = "author_id")
    @JsonBackReference
    private Account author;

    /**
     * Задача, к которой относится комментарий.
     * Связь с {@link Task}, для которой был оставлен комментарий.
     * Каждый комментарий должен быть привязан к конкретной задаче.
     */
    @ManyToOne
    @JoinColumn(name = "task_id")
    @JsonBackReference
    private Task task;

    @Column(name = "posted_at")
    private LocalDateTime postedAt;

    @Column(name = "last_edited_at")
    private LocalDateTime lastEditedAt;
}
