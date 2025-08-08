/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;
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
    value = {
      "SqlStringInjectionHint2-1",
      "SqlStringInjectionHint2-2",
      "SqlStringInjectionHint2-3",
      "SqlStringInjectionHint2-4"
    })
public class SqlInjectionLesson2 implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson2(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack2")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    // Validação simples do parâmetro
    if (query == null || query.trim().isEmpty()) {
      return failed(this).feedback("sql-injection.2.failed").output("Parâmetro inválido").build();
    }
    return injectableQuery(query.trim());
  }

  protected AttackResult injectableQuery(String query) {
    try (var connection = dataSource.getConnection()) {
      String safeQuery = "SELECT department FROM employees WHERE last_name = ?";
      try (PreparedStatement ps = connection.prepareStatement(safeQuery, TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
        ps.setString(1, query);
        try (ResultSet results = ps.executeQuery()) {
          StringBuilder output = new StringBuilder();
          if (results.first()) {
            String department = results.getString("department");
            if ("Marketing".equals(department)) {
              output.append("<span class='feedback-positive'>" + query + "</span>");
              output.append(SqlInjectionLesson8.generateTable(results));
              return success(this).feedback("sql-injection.2.success").output(output.toString()).build();
            } else {
              return failed(this).feedback("sql-injection.2.failed").output(output.toString()).build();
            }
          } else {
            return failed(this).feedback("sql-injection.2.failed").output("Nenhum resultado encontrado").build();
          }
        }
      }
    } catch (SQLException sqle) {
      return failed(this).feedback("sql-injection.2.failed").output(sqle.getMessage()).build();
    } catch (Exception e) {
      return failed(this).feedback("sql-injection.2.failed").output("Erro inesperado: " + e.getMessage()).build();
    }
  }
}
