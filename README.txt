Functions
1. Copy the URL, method, and number of parameters in a format (TSV) that can be pasted into EXCEL.
2. Display the difference (unified_diff) of parameter names from the last request.
3. Format the body in JSON format into x-www-form-urlencoded format. (For CSRF testing)


In the context menu of the request, the following will be added.
1. Extensions> Survey Assistant> Copy URL etc.
    Copy the URL, method, and number of parameters in a TSV format.
2. Extensions> Survey Assistant> Diff Params
    Display the difference (unified_diff) of the parameters from the last request in the "Output" of this Extender in Extender tab.
3. Extensions> Survey Assistant> JSON to URLEncoded
    In Request Editor (Repeater), convert the JSON format body into x-www-form-urlencoded format.
    (Because values other than strings are forcibly casted into strings, null becomes "None", true becomes "True", etc.)