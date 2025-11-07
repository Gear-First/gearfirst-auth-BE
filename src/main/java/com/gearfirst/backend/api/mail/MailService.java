package com.gearfirst.backend.api.mail;

public interface MailService {
    void sendUserRegistrationMail(String toEmail, String password);
}
