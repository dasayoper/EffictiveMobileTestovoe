package by.dasayoper.taskmanager.service;

import by.dasayoper.taskmanager.model.Account;
import by.dasayoper.taskmanager.model.BaseEntity;
import by.dasayoper.taskmanager.security.details.AccountUserDetails;
import by.dasayoper.taskmanager.service.impl.SecurityServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SecurityServiceImplTest {

    @InjectMocks
    private SecurityServiceImpl securityService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Nested
    @DisplayName("getAuthorizedAccount() is working")
    class GetAuthorizedAccountTest {
        @Test
        void getAuthorizedAccount_shouldReturnAuthorizedAccount() {
            Account authorizedAccount = Account.builder()
                    .id(UUID.randomUUID())
                    .firstName("Иван")
                    .lastName("Петров")
                    .email("ivan.petrov@example.com")
                    .role(Account.Role.COMMON_USER)
                    .state(BaseEntity.State.ACTIVE)
                    .build();

            AccountUserDetails accountUserDetails = new AccountUserDetails(authorizedAccount);

            Authentication authentication = mock(Authentication.class);
            when(authentication.getPrincipal()).thenReturn(accountUserDetails);

            SecurityContext securityContext = mock(SecurityContext.class);
            when(securityContext.getAuthentication()).thenReturn(authentication);

            SecurityContextHolder.setContext(securityContext);

            Account result = securityService.getAuthorizedAccount();

            assertEquals(authorizedAccount, result);
        }

        @Test
        void getAuthorizedAccount_shouldThrowAccessDeniedException_WhenNoAuthenticatedUser() {
            SecurityContext securityContext = mock(SecurityContext.class);
            when(securityContext.getAuthentication()).thenReturn(null);

            SecurityContextHolder.setContext(securityContext);

            assertThrows(AccessDeniedException.class, () -> securityService.getAuthorizedAccount());
        }
    }
}
