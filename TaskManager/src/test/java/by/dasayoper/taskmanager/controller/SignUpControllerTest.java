package by.dasayoper.taskmanager.controller;

import by.dasayoper.taskmanager.dto.AccountDto;
import by.dasayoper.taskmanager.dto.form.SignUpForm;
import by.dasayoper.taskmanager.service.SignUpService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class SignUpControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private SignUpService signUpService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Nested
    @DisplayName("signUp() is working")
    class SignUp {
        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void signUp_ShouldReturnCreatedAccount() throws Exception {
            SignUpForm form = SignUpForm.builder()
                    .firstName("John")
                    .lastName("Doe")
                    .email("john.doe@example.com")
                    .password("password123!")
                    .build();
            AccountDto createdAccount = AccountDto.builder()
                    .id(UUID.randomUUID())
                    .firstName("John")
                    .lastName("Doe")
                    .email("john.doe@example.com")
                    .role("COMMON_USER")
                    .build();

            when(signUpService.signUp(any(SignUpForm.class))).thenReturn(createdAccount);

            mockMvc.perform(post("/sign-up")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(form)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.firstName").value("John"))
                    .andExpect(jsonPath("$.lastName").value("Doe"))
                    .andExpect(jsonPath("$.email").value("john.doe@example.com"))
                    .andExpect(jsonPath("$.role").value("COMMON_USER"));
        }

        @Test
        @WithMockUser(username = "testuser", authorities = "ADMIN")
        void signUp_ShouldReturn400BadRequest_WhenFormIsIncorrect() throws Exception {
            SignUpForm form = SignUpForm.builder()
                    .firstName(null)
                    .lastName("")
                    .email("invalid-email")
                    .password("short")
                    .build();

            mockMvc.perform(post("/sign-up")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(form)))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.errors.size()").value(4))
                    .andExpect(jsonPath("$.errors[?(@.field=='firstName')].message")
                            .value("Имя не может быть пустым"))
                    .andExpect(jsonPath("$.errors[?(@.field=='lastName')].message")
                            .value("Фамилия должна начинаться с заглавной буквы, содержать только буквы и иметь длину от 2 до 30 символов"))
                    .andExpect(jsonPath("$.errors[?(@.field=='email')].message")
                            .value("Указан некорректный формат email"))
                    .andExpect(jsonPath("$.errors[?(@.field=='password')].message")
                            .value("Пароль не может быть короче 8 символов и должен содержать хотя бы одну цифру и один специальный символ"));
        }
    }
}

