package by.dasayoper.taskmanager.model;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.util.Set;

/**
 * Сущность задачи.
 * Хранит информацию о задаче, включая её статус, приоритет, описание и связанные объекты.
 * <p>
 * Каждой задаче присваивается уникальный идентификатор {@link BaseEntity#id} и состояние {@link BaseEntity#state}.
 * Статус задачи задается перечислением {@link TaskStatus}.
 * Приоритет задачи задается перечислением {@link TaskPriority}.
 * </p>
 * Также, для каждой задачи хранятся:
 * <ul>
 *     <li>Заголовок задачи {@link #title}.</li>
 *     <li>Описание задачи {@link #description}.</li>
 *     <li>Статус задачи {@link #status}.</li>
 *     <li>Приоритет задачи {@link #priority}.</li>
 *     <li>Список комментариев, связанных с задачей {@link #comments}.</li>
 *     <li>Автор задачи {@link #author}.</li>
 *     <li>Исполнитель задачи {@link #executor}.</li>
 * </ul>
 * </p>
 */
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@SuperBuilder
@ToString
@Entity
@Table(name = "task")
public class Task extends BaseEntity {
    /**
     * Статус задачи.
     * 1. NEW - задача создана, но никому не назначена.
     * 2. ASSIGNED - задача назначена, в работе.
     * 3. DISCUSSION - возникли вопросы по задаче.
     * 4. REVIEW - задача выполнена, но еще не протестирована.
     * 5. APPROVED - задача выполнена и протестирована.
     * 6. REJECTED - задача не принята после проверки.
     * 5. CLOSED - задача утверждена и закрыта.
     */
    public enum TaskStatus {
        NEW, ASSIGNED, DISCUSSION, REVIEW, APPROVED, REJECTED, CLOSED
    }

    /**
     * Приоритет задачи.
     * 1. HIGH - высокий.
     * 2. MEDIUM - средний.
     * 3. LOW - низкий.
     */
    public enum TaskPriority {
        HIGH, MEDIUM, LOW
    }

    private String title;

    private String description;

    @Enumerated(value = EnumType.STRING)
    private TaskStatus status;

    @Enumerated(value = EnumType.STRING)
    private TaskPriority priority;

    /**
     * Список всех комментариев, связанных с задачей.
     * Связь с {@link Comment}, которые были оставлены для этой задачи.
     */
    @OneToMany(mappedBy = "task")
    private Set<Comment> comments;

    /**
     * Автор задачи.
     * Связь с {@link Account}, который создал задачу.
     * Каждая задача должна быть привязан к конкретному пользователю (автору).
     */
    @ManyToOne
    @JoinColumn(name = "author_id")
    @JsonBackReference
    private Account author;

    /**
     * Исполнитель задачи.
     * Связь с {@link Account}, который назначен для выполнения задачи.
     * Задача может быть назначена одному пользователю для выполнения.
     */
    @ManyToOne
    @JoinColumn(name = "executor_id")
    @JsonBackReference
    private Account executor;
}
