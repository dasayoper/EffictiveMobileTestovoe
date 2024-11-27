package by.dasayoper.taskmanager.model;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.util.Set;

/**
 * Сущность аккаунта пользователя.
 * Хранит информацию о пользователе системы, включая его личные данные, роль и связанные объекты.
 * <p>
 * Каждому аккаунту присваивается уникальный идентификатор {@link BaseEntity#id} и состояние {@link BaseEntity#state}.
 * Роль пользователя задается перечислением {@link Role}.
 * </p>
 * Также, для каждого аккаунта хранятся:
 * <ul>
 *     <li>Имя пользователя {@link #firstName}.</li>
 *     <li>Фамилия пользователя {@link #lastName}.</li>
 *     <li>Email {@link #email}, который должен быть уникальным.</li>
 *     <li>Пароль {@link #password}.</li>
 *     <li>Роль {@link #role}, которая может быть либо {@link Role#COMMON_USER}, либо {@link Role#ADMIN}.</li>
 *     <li>Список задач, созданных пользователем {@link #createdTasks}.</li>
 *     <li>Список задач, назначенных пользователю {@link #assignedTasks}.</li>
 *     <li>Список комментариев, созданных пользователем {@link #comments}.</li>
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
@Table(name = "account")
public class Account extends BaseEntity {
    /**
     * Роль пользователя.
     * 1. COMMON_USER - обычный пользователь(задается по умолчанию).
     * 2. ADMIN - администратор.
     */
    public enum Role {
        COMMON_USER, ADMIN
    }

    @Column(name = "first_name")
    private String firstName;

    @Column(name = "last_name")
    private String lastName;

    private String email;

    private String password;

    @Enumerated(value = EnumType.STRING)
    private Role role;

    /**
     * Список задач, созданных пользователем.
     * Связь с сущностью {@link Task}, где пользователь является автором задачи.
     */
    @OneToMany(mappedBy = "author")
    @JsonManagedReference
    private Set<Task> createdTasks;

    /**
     * Список задач, назначенных пользователю.
     * Связь с сущностью {@link Task}, где пользователь является исполнителем задачи.
     */
    @OneToMany(mappedBy = "executor")
    @JsonManagedReference
    private Set<Task> assignedTasks;

    /**
     * Список комментариев, созданных пользователем.
     * Связь с сущностью {@link Comment}, где пользователь является автором комментария.
     */
    @OneToMany(mappedBy = "author")
    @JsonManagedReference
    private Set<Comment> comments;
}
