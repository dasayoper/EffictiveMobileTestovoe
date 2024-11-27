package by.dasayoper.taskmanager.service.impl;

import by.dasayoper.taskmanager.dto.AccountDto;
import by.dasayoper.taskmanager.dto.form.SignUpForm;
import by.dasayoper.taskmanager.exception.AccountAlreadyExistsException;
import by.dasayoper.taskmanager.model.Account;
import by.dasayoper.taskmanager.model.BaseEntity;
import by.dasayoper.taskmanager.repository.AccountRepository;
import by.dasayoper.taskmanager.service.SignUpService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;

import static by.dasayoper.taskmanager.dto.AccountDto.from;

@Service
@RequiredArgsConstructor
public class SignUpServiceImpl implements SignUpService {

    private final AccountRepository accountRepository;
    private final PasswordEncoder passwordEncoder;

    private final Logger LOGGER = LoggerFactory.getLogger(this.getClass());

    /**
     * Регистрация нового пользователя.
     * Проверяет, существует ли аккаунт с указанным в форме email.
     * Если аккаунт с таким email не найден, создает новый аккаунт и сохраняет его в базе данных.
     * В противном случае выбрасывается исключение {@link AccountAlreadyExistsException}.
     *
     * @param form форма регистрации пользователя с полями для создания нового аккаунта
     * @return {@link AccountDto} - объект, представляющий созданный аккаунт
     * @throws AccountAlreadyExistsException если аккаунт с указанным email уже существует
     */
    @Override
    @Transactional
    public AccountDto signUp(SignUpForm form) {
        LOGGER.info("Попытка регистрации пользователя с email: {}", form.getEmail());

        accountRepository.findByEmail(form.getEmail())
                .ifPresent(account -> {
                    LOGGER.info("Неудачная попытка регистрации: пользователь " + form.getEmail() + " уже есть в системе");
                    throw new AccountAlreadyExistsException("Аккаунт с email: " + form.getEmail() + " уже существует");
                });

        Account newAccount = Account.builder()
                .firstName(form.getFirstName())
                .lastName(form.getLastName())
                .email(form.getEmail())
                .password(passwordEncoder.encode(form.getPassword()))
                .role(Account.Role.COMMON_USER)
                .state(BaseEntity.State.ACTIVE)
                .createdTasks(new HashSet<>())
                .assignedTasks(new HashSet<>())
                .comments(new HashSet<>())
                .build();

        Account savedAccount = accountRepository.save(newAccount);
        LOGGER.info("Пользователь с email: {} успешно зарегистрирован.", savedAccount.getEmail());

        return from(savedAccount);
    }
}
