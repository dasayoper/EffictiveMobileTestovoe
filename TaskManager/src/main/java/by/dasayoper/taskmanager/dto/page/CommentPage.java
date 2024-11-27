package by.dasayoper.taskmanager.dto.page;

import by.dasayoper.taskmanager.dto.CommentDto;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * DTO объект, представляющий страницу с комментариями, который используется при применении фильтрации.
 * Используется для передачи данных о странице комментариев и включает в себя список комментариев и информацию о пагинации.
 * <p>
 * Содержит следующие поля:
 * <ul>
 *     <li>Список комментариев {@link #comments}, представленных в виде списка объектов {@link CommentDto}.</li>
 *     <li>Общее количество страниц {@link #totalPages}, доступных для отображения.</li>
 *     <li>Общее количество элементов {@link #totalElements}, доступных для отображения.</li>
 *     <li>Текущая страница {@link #currentPage}, которая отображается в данный момент.</li>
 * </ul>
 * </p>
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Schema(description = "Страница с комментариями с поддержкой пагинации")
public class CommentPage {
    @Schema(description = "Список комментариев")
    private List<CommentDto> comments;

    @Schema(description = "Общее количество страниц")
    private Integer totalPages;

    @Schema(description = "Общее количество элементов")
    private Long totalElements;

    @Schema(description = "Текущая страница")
    private Integer currentPage;
}
