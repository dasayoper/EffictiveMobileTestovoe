package by.dasayoper.taskmanager.service;

import by.dasayoper.taskmanager.dto.AccountDto;
import by.dasayoper.taskmanager.dto.form.SignUpForm;
import by.dasayoper.taskmanager.exception.AccountAlreadyExistsException;
import by.dasayoper.taskmanager.model.Account;
import by.dasayoper.taskmanager.model.BaseEntity;
import by.dasayoper.taskmanager.repository.AccountRepository;
import by.dasayoper.taskmanager.service.impl.SignUpServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class SignUpServiceImplTest {

    @Mock
    private AccountRepository accountRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private SignUpServiceImpl signUpService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void signUp_shouldReturnAccountDto_whenAccountDoesNotExist() {
        SignUpForm form = SignUpForm.builder()
                .firstName("Иван")
                .lastName("Петров")
                .email("ivan.petrov@example.com")
                .password("password123!")
                .build();

        Account newAccount = Account.builder()
                .firstName("Иван")
                .lastName("Петров")
                .email("ivan.petrov@example.com")
                .password("encodedPassword")
                .role(Account.Role.COMMON_USER)
                .state(BaseEntity.State.ACTIVE)
                .createdTasks(new HashSet<>())
                .assignedTasks(new HashSet<>())
                .comments(new HashSet<>())
                .build();

        when(accountRepository.findByEmail(form.getEmail())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(form.getPassword())).thenReturn("encodedPassword");
        when(accountRepository.save(any(Account.class))).thenReturn(newAccount);

        AccountDto accountDto = signUpService.signUp(form);

        assertNotNull(accountDto);
        assertEquals("ivan.petrov@example.com", accountDto.getEmail());
        assertEquals("COMMON_USER", accountDto.getRole());
        verify(accountRepository).save(any(Account.class));
    }

    @Test
    void signUp_shouldThrowAccountAlreadyExistsException_whenAccountAlreadyExists() {
        SignUpForm form = SignUpForm.builder()
                .firstName("Иван")
                .lastName("Петров")
                .email("ivan.petrov@example.com")
                .password("password123!")
                .build();

        Account existingAccount = Account.builder()
                .firstName("Иван")
                .lastName("Петров")
                .email("ivan.petrov@example.com")
                .password("encodedPassword")
                .role(Account.Role.COMMON_USER)
                .state(BaseEntity.State.ACTIVE)
                .createdTasks(new HashSet<>())
                .assignedTasks(new HashSet<>())
                .comments(new HashSet<>())
                .build();

        when(accountRepository.findByEmail(form.getEmail())).thenReturn(Optional.of(existingAccount));

        AccountAlreadyExistsException exception = assertThrows(AccountAlreadyExistsException.class, () -> signUpService.signUp(form));
        assertEquals("Аккаунт с email: ivan.petrov@example.com уже существует", exception.getMessage());
        verify(accountRepository, never()).save(any(Account.class));
    }
}
