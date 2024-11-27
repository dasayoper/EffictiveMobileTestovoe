package by.dasayoper.taskmanager.dto.page;

import by.dasayoper.taskmanager.dto.AccountDto;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * DTO объект, представляющий страницу с аккаунтами, который используется при применении фильтрации.
 * Используется для передачи данных о странице аккаунтов и включает в себя список аккаунтов и информацию о пагинации.
 * <p>
 * Содержит следующие поля:
 * <ul>
 *     <li>Список аккаунтов {@link #accounts}, представленных в виде списка объектов {@link AccountDto}.</li>
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
@Schema(description = "Страница с аккаунтами пользователей с поддержкой пагинации")
public class AccountPage {
    @Schema(description = "Список аккаунтов пользователей")
    private List<AccountDto> accounts;

    @Schema(description = "Общее количество страниц")
    private Integer totalPages;

    @Schema(description = "Общее количество элементов")
    private Long totalElements;

    @Schema(description = "Текущая страница")
    private Integer currentPage;
}
