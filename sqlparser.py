import re
import main

prompt = 'oursql> '
prompt2 = ' '*5 + '-> '


def sql_execute_equ(col_names, table_name, condition):
    if condition is not None:
        col = condition[0].upper()
        if col == 'ID' and main.id_rnd:
            main.adjust('ID')
        if col == 'NAME' and main.name_rnd:
            main.adjust('NAME')
    enc_table = main.select(condition)
    return main.decrypt_result(col_names, enc_table)


def print_to_console(col_names, tmp_table):
    if len(tmp_table) == 0:
        return
    print('----------------------------------------')
    if len(col_names) == 1 and col_names[0] == '*':
        print('ID', 'NAME')
        for row in tmp_table:
            print(' '.join([str(item) for item in row]))
        print('----------------------------------------')
        return
    col_names = [c.upper() for c in col_names]
    print(' '.join(col_names))
    index = []
    for n in col_names:
        if n == 'ID':
            index.append(0)
        if n == 'NAME':
            index.append(1)
    for row in tmp_table:
        print(' '.join([str(row[i]) for i in index]))
    print('----------------------------------------')


def sql_execute(sql):
    try:
        command, sql_rest = sql.split(maxsplit=1)
    except:
        print('命令不支持')
        return
    sql_rest = sql_rest.rstrip()
    if command == 'select':
        re_pattern1 = r'^([\w,*]+)\s+from\s+(\w+)$'
        re_pattern2 = r'^([\w,*]+)\s+from\s+(\w+)\s+where\s+(.*)$'
        m = re.match(re_pattern1, sql_rest) or re.match(re_pattern2, sql_rest)
        if m:
            col_names = [colname.strip().capitalize() for colname in m.group(1).split(',')]
            table_name = m.group(2)
            condition = None

            if len(m.groups()) == 3:
                condition = m.group(3)
                con_pattern = r'^(\w+)\s*=\s*(.*)$'
                m = re.match(con_pattern, condition)
                if m is None:
                    print('where 语法不支持')
                    return
                condition = [item for item in m.groups()]
            tmp_table = sql_execute_equ(col_names, table_name, condition)
            print_to_console(col_names, tmp_table)

        else:
            print('select 语法不支持')
    else:
        print('不支持' + command + '操作')

while True:
    sql = input(prompt).strip()
    if sql == 'exit' or sql == 'exit;':
        print('Bye')
        break
    if sql is None or len(sql) == 0:
        continue
    while sql[-1] != ';':
        sql += input(prompt2)
    sql.rstrip()
    sql_execute(sql[0:-1])
