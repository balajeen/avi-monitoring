*** Settings ***
Documentation     resource file for controller testsuites
Library           api/vs_lib_v2.py
Library           api/se_validations_lib.py
Library           tools/collect_techsupport.py
Library           Collections
Library           OperatingSystem
Library           String
Library           api.controller_lib.TechSupport   WITH NAME   TechSupport

*** Variables ***
${timeout}        10

*** Keywords ***
no_arg_keyword
    LOG    no_args

args_keyword
    [Arguments]   @{args}
    : FOR    ${arg}     IN    ${args}
    \    LOG    ${arg}

vs_is_well
    [Arguments]   ${vs_name}    ${name-ext}    ${timeout}=${timeout}
    Set Suite Variable    \${${vs_name}_${name-ext}}    ${timeout}
