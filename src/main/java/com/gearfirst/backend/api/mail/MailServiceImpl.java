package com.gearfirst.backend.api.mail;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;

@Slf4j
@Service
@RequiredArgsConstructor
public class MailServiceImpl implements MailService {
    private final JavaMailSender mailSender;

    @Value("${mail.sender.address}")
    private String senderAddress;   //  Gmail 주소 (spring.mail.username)

    @Value("${mail.sender.name}")
    private String senderName;      //  표시 이름 (“GearFirst 운영팀”)

    @Override
    public void sendUserRegistrationMail(String toEmail, String tempPassword) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setTo(toEmail);
            helper.setFrom(senderAddress, senderName);
            helper.setSubject("[GearFirst] 신규 계정 안내");
            helper.setText(buildMailContent(tempPassword), true);
            mailSender.send(message);

        } catch (MessagingException | UnsupportedEncodingException e) {
            throw new RuntimeException("이메일 전송 실패: " + e.getMessage());
        }
    }

private String buildMailContent(String tempPassword) {
    return """
        <div style="max-width:600px;margin:30px auto;padding:30px;
                    font-family:'Segoe UI',Arial,sans-serif;
                    background-color:#f9f9f9;border-radius:10px;
                    box-shadow:0 2px 10px rgba(0,0,0,0.08);">
            <div style="text-align:center;margin-bottom:30px;">
                <h2 style="color:#2d2d2d;font-weight:700;margin-bottom:10px;">
                    안녕하세요!
                </h2>
                <p style="color:#555;font-size:16px;margin:0;">
                    <b>GearFirst</b> 시스템에 새로운 계정이 생성되었습니다.
                </p>
            </div>

            <div style="background-color:#ffffff;border:1px solid #e2e2e2;
                        border-radius:8px;padding:20px 25px;text-align:center;">
                <p style="font-size:16px;color:#333;margin-bottom:10px;">
                    <b>임시 비밀번호</b>
                </p>
                <p style="font-size:22px;font-weight:bold;color:#0078d7;
                          letter-spacing:1px;margin:0;">
                    %s
                </p>
            </div>

            <div style="margin-top:30px;color:#444;font-size:15px;line-height:1.8;">
                <p>처음 로그인 후 반드시 비밀번호를 변경해주세요.</p>
                <p>보안을 위해 타인과 공유하지 말아주세요.</p>
                <p style="margin-top:25px;">감사합니다.<br/>
                <strong style="color:#0078d7;">GearFirst 운영팀</strong> 드림</p>
            </div>

            <hr style="margin-top:30px;border:none;border-top:1px solid #ddd;">
            <p style="text-align:center;font-size:12px;color:#888;margin-top:15px;">
                ⓒ 2025 GearFirst. All rights reserved.
            </p>
        </div>
    """.formatted(tempPassword);
}

}
