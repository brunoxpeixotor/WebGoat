/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {"SqlStringInjectionHint4-1", "SqlStringInjectionHint4-2", "SqlStringInjectionHint4-3"})
public class SqlInjectionLesson4 implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson4(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack4")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    // Validação simples do parâmetro
    if (query == null || query.trim().isEmpty()) {
      return failed(this).output("Parâmetro inválido").build();
    }
    return injectableQuery(query.trim());
  }

  protected AttackResult injectableQuery(String query) {
    try (Connection connection = dataSource.getConnection()) {
      String updateQuery = "UPDATE employees SET phone = ? WHERE last_name = ?";
      try (PreparedStatement ps = connection.prepareStatement(updateQuery)) {
        // Exemplo: query esperado: "UPDATE employees SET phone = '123' WHERE last_name = 'Smith'"
        // Aqui, para fins didáticos, vamos simular a extração dos parâmetros (em produção, use parser SQL ou lógica robusta)
        String[] parts = query.split("'");
        if (parts.length >= 4) {
          String phone = parts[1];
          String lastName = parts[3];
          ps.setString(1, phone);
          ps.setString(2, lastName);
          ps.executeUpdate();
          connection.commit();
        } else {
          return failed(this).output("Formato de query inválido").build();
        }
        try (PreparedStatement ps2 = connection.prepareStatement("SELECT phone from employees WHERE last_name = ?")) {
          ps2.setString(1, parts.length >= 4 ? parts[3] : "");
          ResultSet results = ps2.executeQuery();
          StringBuilder output = new StringBuilder();
          if (results.first()) {
            output.append("<span class='feedback-positive'>").append(query).append("</span>");
            return success(this).output(output.toString()).build();
          } else {
            return failed(this).output(output.toString()).build();
          }
        }
      } catch (SQLException sqle) {
        return failed(this).output(sqle.getMessage()).build();
      }
    } catch (Exception e) {
      return failed(this).output(this.getClass().getName() + " : " + e.getMessage()).build();
    }
  }
}
