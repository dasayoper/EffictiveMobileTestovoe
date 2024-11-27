package by.dasayoper.taskmanager.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import org.hibernate.annotations.GenericGenerator;

import java.util.UUID;

/**
 * Базовая сущность для всех сущностей в системе.
 * Хранит общие поля, такие как уникальный идентификатор {@link #id} и состояние сущности {@link #state}.
 * <p>
 * Этот класс является родительским для других сущностей
 * </p>
 */
@Data
@SuperBuilder
@MappedSuperclass
@NoArgsConstructor
@AllArgsConstructor
public class BaseEntity {
    /**
     * Перечисление, представляющее возможные состояния сущности.
     * {@link State#ACTIVE} - активная сущность, которая используется в системе.
     * {@link State#DELETED} - сущность помечена как удаленная и не должна использоваться в результирующих выборках.
     */
    public enum State {
        ACTIVE, DELETED
    }

    /**
     * Уникальный идентификатор сущности.
     * Генерируется автоматически с использованием стратегии UUID.
     */
    @Id
    @GeneratedValue(generator = "UUID")
    @GenericGenerator(name = "UUID", strategy = "org.hibernate.id.UUIDGenerator")
    private UUID id;

    /**
     * Состояние сущности.
     * Может быть {@link State#ACTIVE}  или {@link State#DELETED}.
     * Поле может использоваться для логического удаления объектов, не удаляя их физически из базы данных (soft delete).
     */
    @Enumerated(value = EnumType.STRING)
    private State state;
}
