package by.dasayoper.taskmanager.service;

import by.dasayoper.taskmanager.dto.AccountDto;
import by.dasayoper.taskmanager.dto.form.AccountInfoForm;
import by.dasayoper.taskmanager.dto.page.AccountPage;
import by.dasayoper.taskmanager.dto.util.AccountFilterParameters;
import by.dasayoper.taskmanager.exception.NotEnoughRightsException;
import by.dasayoper.taskmanager.exception.UserAccountNotFoundException;
import by.dasayoper.taskmanager.model.Account;
import by.dasayoper.taskmanager.model.BaseEntity;
import by.dasayoper.taskmanager.model.Task;
import by.dasayoper.taskmanager.repository.AccountRepository;
import by.dasayoper.taskmanager.service.impl.AccountServiceImpl;
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

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

public class AccountServiceImplTest {

    @Mock
    private AccountRepository accountRepository;

    @Mock
    private SecurityService securityService;

    @InjectMocks
    private AccountServiceImpl accountService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Nested
    @DisplayName("getById() is working")
    class GetByIdTest {
        @Test
        void getById_shouldReturnAccount_whenAccountExists() {
            UUID accountId = UUID.randomUUID();
            Account account = Account.builder()
                    .id(accountId)
                    .firstName("John")
                    .lastName("Doe")
                    .email("john.doe@example.com")
                    .role(Account.Role.COMMON_USER)
                    .state(BaseEntity.State.ACTIVE)
                    .build();

            when(accountRepository.findById(accountId)).thenReturn(Optional.of(account));

            AccountDto accountDto = accountService.getById(accountId);

            assertNotNull(accountDto);
            assertEquals("John", accountDto.getFirstName());
        }

        @Test
        void getById_shouldThrowException_whenAccountDoesNotExist() {
            UUID accountId = UUID.randomUUID();

            when(accountRepository.findById(accountId)).thenReturn(Optional.empty());

            assertThrows(UserAccountNotFoundException.class, () -> accountService.getById(accountId));
        }
    }

    @Test
    void getAll_shouldReturnAllAccounts() {
        List<Account> accounts = List.of(
                Account.builder()
                        .id(UUID.randomUUID())
                        .firstName("John")
                        .lastName("Doe")
                        .email("john.doe@example.com")
                        .role(Account.Role.COMMON_USER)
                        .state(BaseEntity.State.ACTIVE)
                        .build(),
                Account.builder()
                        .id(UUID.randomUUID())
                        .firstName("Jane")
                        .lastName("Smith")
                        .email("jane.smith@example.com")
                        .role(Account.Role.ADMIN)
                        .state(BaseEntity.State.ACTIVE)
                        .build()
        );

        when(accountRepository.findAll()).thenReturn(accounts);

        List<AccountDto> accountDtoList = accountService.getAll();

        assertNotNull(accountDtoList);
        assertEquals(2, accountDtoList.size());

        AccountDto firstAccountDto = accountDtoList.get(0);
        assertEquals("John", firstAccountDto.getFirstName());

        AccountDto secondAccountDto = accountDtoList.get(1);
        assertEquals("Jane", secondAccountDto.getFirstName());
    }

    @Nested
    @DisplayName("getAllFiltered() is working")
    class GetAllFilteredTests {

        @Test
        void getAllFiltered_shouldReturnAllAccounts_WhenNoFiltersApplied() {
            List<Account> accounts = List.of(
                    Account.builder()
                            .id(UUID.randomUUID())
                            .firstName("John")
                            .lastName("Doe")
                            .email("john.doe@example.com")
                            .role(Account.Role.COMMON_USER)
                            .state(BaseEntity.State.ACTIVE)
                            .build(),
                    Account.builder()
                            .id(UUID.randomUUID())
                            .firstName("Jane")
                            .lastName("Smith")
                            .email("jane.smith@example.com")
                            .role(Account.Role.ADMIN)
                            .state(BaseEntity.State.ACTIVE)
                            .build()
            );

            AccountFilterParameters filterParameters = AccountFilterParameters.buildAccountFilterParameters(null, null, null, null, 0, 10);

            Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
            Page<Account> accountPage = new PageImpl<>(accounts, pageable, accounts.size());
            when(accountRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(accountPage);

            AccountPage result = accountService.getAllFiltered(filterParameters);

            assertNotNull(result);
            assertEquals(2, result.getAccounts().size());
            assertEquals(1, result.getTotalPages());
        }

        @Test
        void getAllFiltered_shouldFilterAccounts_ByFirstName() {
            List<Account> accounts = List.of(
                    Account.builder()
                            .id(UUID.randomUUID())
                            .firstName("John")
                            .lastName("Doe")
                            .email("john.doe@example.com")
                            .role(Account.Role.COMMON_USER)
                            .state(BaseEntity.State.ACTIVE)
                            .build()
            );

            AccountFilterParameters filterParameters = AccountFilterParameters.buildAccountFilterParameters("John", null, null, null, 0, 10);

            Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
            Page<Account> accountPage = new PageImpl<>(accounts, pageable, accounts.size());
            when(accountRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(accountPage);

            AccountPage result = accountService.getAllFiltered(filterParameters);

            assertNotNull(result);
            assertEquals(1, result.getAccounts().size());
            assertEquals("John", result.getAccounts().get(0).getFirstName());
        }

        @Test
        void getAllFiltered_shouldFilterAccounts_ByLastName() {
            List<Account> accounts = List.of(
                    Account.builder()
                            .id(UUID.randomUUID())
                            .firstName("Jane")
                            .lastName("Smith")
                            .email("jane.smith@example.com")
                            .role(Account.Role.ADMIN)
                            .state(BaseEntity.State.ACTIVE)
                            .build()
            );

            AccountFilterParameters filterParameters = AccountFilterParameters.buildAccountFilterParameters(null, "Smith", null, null, 0, 10);

            Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
            Page<Account> accountPage = new PageImpl<>(accounts, pageable, accounts.size());
            when(accountRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(accountPage);

            AccountPage result = accountService.getAllFiltered(filterParameters);

            assertNotNull(result);
            assertEquals(1, result.getAccounts().size());
            assertEquals("Smith", result.getAccounts().get(0).getLastName());
        }

        @Test
        void getAllFiltered_shouldFilterAccounts_ByEmail() {
            List<Account> accounts = List.of(
                    Account.builder()
                            .id(UUID.randomUUID())
                            .firstName("John")
                            .lastName("Doe")
                            .email("john.doe@example.com")
                            .role(Account.Role.COMMON_USER)
                            .state(BaseEntity.State.ACTIVE)
                            .build()
            );

            AccountFilterParameters filterParameters = AccountFilterParameters.buildAccountFilterParameters(null, null, "john.doe@example.com", null, 0, 10);

            Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
            Page<Account> accountPage = new PageImpl<>(accounts, pageable, accounts.size());
            when(accountRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(accountPage);

            AccountPage result = accountService.getAllFiltered(filterParameters);

            assertNotNull(result);
            assertEquals(1, result.getAccounts().size());
            assertEquals("john.doe@example.com", result.getAccounts().get(0).getEmail());
        }

        @Test
        void getAllFiltered_shouldFilterAccounts_ByHasAssignedTasks() {
            Account account = Account.builder()
                    .id(UUID.randomUUID())
                    .firstName("John")
                    .lastName("Doe")
                    .email("john.doe@example.com")
                    .role(Account.Role.COMMON_USER)
                    .state(BaseEntity.State.ACTIVE)
                    .assignedTasks(new HashSet<>())
                    .build();

            account.getAssignedTasks().add(new Task("Задача 1", "Описание", Task.TaskStatus.ASSIGNED, Task.TaskPriority.LOW, new HashSet<>(), account, account));

            List<Account> accounts = List.of(account);

            AccountFilterParameters filterParameters = AccountFilterParameters.buildAccountFilterParameters(null, null, null, "false", 0, 10);

            Pageable pageable = PageRequest.of(filterParameters.getPage(), filterParameters.getSize());
            Page<Account> accountPage = new PageImpl<>(accounts, pageable, accounts.size());
            when(accountRepository.findAll(any(Specification.class), eq(pageable))).thenReturn(accountPage);

            AccountPage result = accountService.getAllFiltered(filterParameters);

            assertNotNull(result);
            assertEquals(1, result.getAccounts().size());
        }
    }

    @Nested
    @DisplayName("updateById() is working")
    class UpdateByIdTest {
        @Test
        void updateById_shouldUpdateAccount_whenUserHasRights() {
            UUID accountId = UUID.randomUUID();
            Account account = Account.builder()
                    .id(accountId)
                    .firstName("John")
                    .lastName("Doe")
                    .email("john.doe@example.com")
                    .role(Account.Role.COMMON_USER)
                    .state(BaseEntity.State.ACTIVE)
                    .build();

            AccountInfoForm form = AccountInfoForm.builder()
                    .firstName("Jane")
                    .lastName("Doe")
                    .build();

            when(accountRepository.findById(accountId)).thenReturn(Optional.of(account));
            when(securityService.getAuthorizedAccount()).thenReturn(account);
            when(accountRepository.save(any(Account.class))).thenReturn(account);

            AccountDto updatedAccountDto = accountService.updateById(accountId, form);

            assertNotNull(updatedAccountDto);
            assertEquals("Jane", updatedAccountDto.getFirstName());
            assertEquals("Doe", updatedAccountDto.getLastName());
        }

        @Test
        void updateById_shouldThrowException_whenUserDoesNotHaveRights() {
            UUID accountId = UUID.randomUUID();
            Account account = Account.builder()
                    .id(accountId)
                    .firstName("John")
                    .lastName("Doe")
                    .email("john.doe@example.com")
                    .role(Account.Role.COMMON_USER)
                    .state(BaseEntity.State.ACTIVE)
                    .build();

            AccountInfoForm form = AccountInfoForm.builder()
                    .firstName("Jane")
                    .lastName("Doe")
                    .build();

            Account authorizedAccount = Account.builder()
                    .id(UUID.randomUUID())
                    .firstName("User")
                    .lastName("Userov")
                    .email("user@example.com")
                    .role(Account.Role.COMMON_USER)
                    .state(BaseEntity.State.ACTIVE)
                    .build();

            when(accountRepository.findById(accountId)).thenReturn(Optional.of(account));
            when(securityService.getAuthorizedAccount()).thenReturn(authorizedAccount);

            assertThrows(NotEnoughRightsException.class, () -> accountService.updateById(accountId, form));
        }
    }
}
