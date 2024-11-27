package by.dasayoper.taskmanager.controller;

import by.dasayoper.taskmanager.dto.form.SignInForm;
import by.dasayoper.taskmanager.model.Account;
import by.dasayoper.taskmanager.model.BaseEntity;
import by.dasayoper.taskmanager.security.details.AccountUserDetails;
import by.dasayoper.taskmanager.security.utils.JwtUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private AuthenticationManager authenticationManager;

    @MockBean
    private JwtUtils jwtUtils;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Nested
    @DisplayName("login() is working")
    class Login {
        @Test
        void login_ShouldReturnAccessAndRefreshTokens_WhenCredentialsAreValid() throws Exception {
            SignInForm signInForm = SignInForm.builder()
                    .email("test@example.com")
                    .password("password123!")
                    .build();

            AccountUserDetails accountUserDetails = new AccountUserDetails(Account.builder()
                    .id(UUID.randomUUID())
                    .email("test@example.com")
                    .password("password123!")
                    .role(Account.Role.COMMON_USER)
                    .state(BaseEntity.State.ACTIVE)
                    .build());

            Authentication authentication = new UsernamePasswordAuthenticationToken(accountUserDetails, null, accountUserDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(authentication);

            when(authenticationManager.authenticate(any())).thenReturn(authentication);
            when(jwtUtils.createAccessToken(any(AccountUserDetails.class))).thenReturn("mockAccessToken");
            when(jwtUtils.createRefreshToken(any(AccountUserDetails.class))).thenReturn("mockRefreshToken");

            mockMvc.perform(post("/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(signInForm)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").value("mockAccessToken"))
                    .andExpect(jsonPath("$.refreshToken").value("mockRefreshToken"));
        }

        @Test
        void login_ShouldReturn401Unauthorized_WhenCredentialsAreInvalid() throws Exception {
            SignInForm signInForm = SignInForm.builder()
                    .email("invalid@example.com")
                    .password("wrongpassword")
                    .build();

            mockMvc.perform(post("/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(signInForm)))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("Неверные данные для входа"));
        }
    }

    @Nested
    @DisplayName("refresh() is working")
    class Refresh {
        @Test
        void refresh_ShouldReturnNewAccessToken_WhenRefreshTokenIsValid() throws Exception {
            Map<String, String> request = Map.of("refreshToken", "validRefreshToken");

            when(jwtUtils.validateToken("validRefreshToken")).thenReturn(true);
            when(jwtUtils.createAccessTokenFromRefreshToken("validRefreshToken")).thenReturn("newAccessToken");

            mockMvc.perform(post("/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").value("newAccessToken"));
        }

        @Test
        void refresh_ShouldReturn401Unauthorized_WhenRefreshTokenIsInvalid() throws Exception {
            Map<String, String> request = Map.of("refreshToken", "invalidRefreshToken");

            when(jwtUtils.validateToken("invalidRefreshToken")).thenReturn(false);

            mockMvc.perform(post("/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("Неверный или истекший refresh-токен"));
        }
    }
}

