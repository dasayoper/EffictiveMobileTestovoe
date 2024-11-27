package by.dasayoper.taskmanager.service.impl;

import by.dasayoper.taskmanager.dto.AccountDto;
import by.dasayoper.taskmanager.dto.form.AccountInfoForm;
import by.dasayoper.taskmanager.dto.page.AccountPage;
import by.dasayoper.taskmanager.dto.util.AccountFilterParameters;
import by.dasayoper.taskmanager.exception.NotEnoughRightsException;
import by.dasayoper.taskmanager.exception.UserAccountNotFoundException;
import by.dasayoper.taskmanager.model.Account;
import by.dasayoper.taskmanager.repository.AccountRepository;
import by.dasayoper.taskmanager.service.AccountService;
import by.dasayoper.taskmanager.service.SecurityService;
import by.dasayoper.taskmanager.specification.AccountSpecification;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

import static by.dasayoper.taskmanager.dto.AccountDto.from;

@Service
@RequiredArgsConstructor
public class AccountServiceImpl implements AccountService {

    private final AccountRepository accountRepository;
    private final SecurityService securityService;

    private final Logger LOGGER = LoggerFactory.getLogger(this.getClass());

    /**
     * Получение аккаунта по идентификатору.
     *
     * @param id уникальный идентификатор аккаунта.
     * @return объект {@link AccountDto}, представляющий найденный аккаунт.
     * @throws UserAccountNotFoundException если аккаунт с указанным id не найден.
     */
    @Override
    public AccountDto getById(UUID id) {
        LOGGER.info("Попытка получения аккаунта с id: {}", id);
        AccountDto accountDto = from(findAccountById(id));
        LOGGER.info("Аккаунт с id: {} успешно найден", id);
        return accountDto;
    }

    /**
     * Получение списка всех аккаунтов.
     *
     * @return список всех аккаунтов в виде {@link AccountDto}.
     */
    @Override
    public List<AccountDto> getAll() {
        LOGGER.info("Запрос на получение всех аккаунтов");
        List<AccountDto> accounts = from(accountRepository.findAll());
        LOGGER.info("Получено {} аккаунтов", accounts.size());
        return accounts;
    }

    /**
     * Получение аккаунтов с фильтрацией и пагинацией.
     *
     * @param filterParameters параметры фильтрации аккаунтов {@link AccountFilterParameters}.
     * @return объект {@link AccountPage}, содержащий список аккаунтов в виде {@link AccountDto} и данные о пагинации.
     */
    @Override
    public AccountPage getAllFiltered(AccountFilterParameters filterParameters) {
        LOGGER.info("Запрос на получение аккаунтов с фильтрацией по параметрам: {}", filterParameters);
        Specification<Account> specification = buildAccountSpecification(filterParameters);

        Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
        Page<Account> accountPage = accountRepository.findAll(specification, pageable);

        LOGGER.info("Найдено {} аккаунтов, всего страниц: {}, элементов {}",
                accountPage.getContent().size(),
                pageable.getPageNumber(),
                accountPage.getTotalElements());

        return AccountPage.builder()
                .accounts(from(accountPage.getContent()))
                .totalPages(accountPage.getTotalPages())
                .totalElements(accountPage.getTotalElements())
                .currentPage(pageable.getPageNumber())
                .build();
    }

    /**
     * Обновление информации об аккаунте по идентификатору.
     * Обновление разрешено только для текущего пользователя или для администратора.
     *
     * @param id   уникальный идентификатор аккаунта.
     * @param form данные для обновления аккаунта.
     * @return обновленный объект {@link AccountDto}.
     * @throws NotEnoughRightsException если текущий пользователь не имеет прав на обновление.
     * @throws UserAccountNotFoundException если аккаунт с указанным id не найден.
     */
    @Override
    public AccountDto updateById(UUID id, AccountInfoForm form) {
        LOGGER.info("Попытка обновления аккаунта с id: {}", id);
        Account account = findAccountById(id);

        if (account.getId().equals(securityService.getAuthorizedAccount().getId())
                || securityService.getAuthorizedAccount().getRole().equals(Account.Role.ADMIN)) {

            account.setFirstName(form.getFirstName());
            account.setLastName(form.getLastName());

            AccountDto updatedAccount = from(accountRepository.save(account));
            LOGGER.info("Аккаунт с id: {} успешно обновлен", id);
            return updatedAccount;
        } else {
            LOGGER.error("Недостаточно прав для обновления аккаунта с id: {}", id);
            throw new NotEnoughRightsException("Недостаточно прав для этой операции");
        }
    }

    /**
     * Вспомогательный метод для поиска аккаунта по идентификатору.
     *
     * @param id уникальный идентификатор аккаунта.
     * @return найденный объект {@link Account}.
     * @throws UserAccountNotFoundException если аккаунт с указанным id не найден.
     */
    private Account findAccountById(UUID id) {
        LOGGER.debug("Попытка получения аккаунта с id: {}", id);
        return accountRepository.findById(id)
                .orElseThrow(() -> {
                    LOGGER.error("Аккаунт с id: {} не найден", id);
                    return new UserAccountNotFoundException("Аккаунт с id: " + id + " не найден");
                });
    }

    /**
     * Вспомогательный метод для создания спецификации для фильтрации аккаунтов.
     *
     * @param filterParameters параметры фильтрации аккаунтов {@link AccountFilterParameters}.
     * @return объект {@link Specification<Account>} для поиска.
     */
    private Specification<Account> buildAccountSpecification(AccountFilterParameters filterParameters) {
        LOGGER.debug("Создание спецификации для фильтрации: {}", filterParameters);

        Specification<Account> specification = Specification.where(AccountSpecification.notDeleted());

        if (filterParameters.getFirstName() != null && !filterParameters.getFirstName().isBlank()) {
            specification = specification.and(AccountSpecification.firstNameContains(filterParameters.getFirstName()));
        }

        if (filterParameters.getLastName() != null && !filterParameters.getLastName().isBlank()) {
            specification = specification.and(AccountSpecification.lastNameContains(filterParameters.getLastName()));
        }

        if (filterParameters.getEmail() != null && !filterParameters.getEmail().isBlank()) {
            specification = specification.and(AccountSpecification.emailContains(filterParameters.getEmail()));
        }

        if (filterParameters.getHasAssignedTasks() != null && !filterParameters.getHasAssignedTasks().isBlank()) {
            String hasAssignedTasksValue = filterParameters.getHasAssignedTasks().toLowerCase();
            if ("true".equals(hasAssignedTasksValue)) {
                specification = specification.and(AccountSpecification.hasAssignedTasks(true));
            } else if ("false".equals(hasAssignedTasksValue)) {
                specification = specification.and(AccountSpecification.hasAssignedTasks(false));
            }
        }

        LOGGER.debug("Спецификация создана");
        return specification;
    }
}
