[Version = "2.1.0"]
section JamfPro;

// Number of computer or mobile device records to request per page.
PAGE_SIZE = 100;

// All supported sections for v4 computer inventory endpoint.
COMPUTER_INVENTORY_SECTIONS = {
    "GENERAL", "DISK_ENCRYPTION", "PURCHASING", "APPLICATIONS", "STORAGE", "USER_AND_LOCATION",
    "CONFIGURATION_PROFILES", "PRINTERS", "SERVICES", "HARDWARE", "LOCAL_USER_ACCOUNTS",
    "CERTIFICATES", "ATTACHMENTS", "PACKAGE_RECEIPTS", "SECURITY", "OPERATING_SYSTEM",
    "LICENSED_SOFTWARE", "IBEACONS", "SOFTWARE_UPDATES", "EXTENSION_ATTRIBUTES", "CONTENT_CACHING",
    "GROUP_MEMBERSHIPS"
};

// All supported sections for v2 mobile device inventory detail endpoint.
MOBILE_DEVICE_INVENTORY_SECTIONS = {
    "GENERAL", "HARDWARE", "USER_AND_LOCATION", "PURCHASING", "SECURITY", "APPLICATIONS", "EBOOKS",
    "NETWORK", "SERVICE_SUBSCRIPTIONS", "CERTIFICATES", "PROFILES", "USER_PROFILES",
    "PROVISIONING_PROFILES", "SHARED_USERS", "GROUPS", "EXTENSION_ATTRIBUTES"
};

[DataSource.Kind = "JamfPro", Publish = "JamfPro.Publish"]
// gets initial jamf URL from user; uses this to make requests
shared JamfPro.Contents = Value.ReplaceType(
    JamfPro.JamfNavTable,
    type function (
        jamfUrl as (
            Uri.Type meta [
                Documentation.Name = Extension.LoadString("FunctionParamJamfUrlName"),
                Documentation.FieldCaption = Extension.LoadString("FunctionParamJamfUrlFieldCaption"),
                Documentation.FieldDescription = Extension.LoadString("FunctionParamJamfUrlFieldDescription"),
                Documentation.FieldSampleValues = {"https://acme.jamfcloud.com"}
            ]
        )
    ) as text meta [
        Documentation.Name = Extension.LoadString("FunctionName")
    ]
);

// sets initial navigation table that links to individual table queries
shared JamfPro.JamfNavTable = (url as text) as table =>
    let
        url = validateUrlScheme(url),
        computerPages = getTotalNumberOfPages(url, "v4/computers-inventory"),
        mobileDevicesPages = getTotalNumberOfPages(url, "v2/mobile-devices"),
        source = #table(
            {"Name", "Data", "ItemKind", "ItemName", "IsLeaf"},
            {
                {"Computers", computers(url, computerPages), "Table", "Table", true},
                {"Computers - Storage", computerStorage(url, computerPages), "Table", "Table", true},
                {"Computers - Patch Status", computerPatchStatus(url), "Table", "Table", true},
                {"Computer Device Groups", computerGroups(url), "Table", "Table", true},
                {"Computers - Applications", computerApplications(url, computerPages), "Table", "Table", true},
                {"Computers - Extension attributes", computerExtensionAttributes(url, computerPages), "Table", "Table", true},
                {"Mobile Devices", mobileDevices(url, mobileDevicesPages), "Table", "Table", true},
                {"Mobile - Applications", mobileDeviceApplications(url, mobileDevicesPages), "Table", "Table", true},
                {"Mobile Device Groups", mobileDeviceGroups(url), "Table", "Table", true},
                {"Mobile Devices - ExtensionAttributes", mobileDeviceExtensionAtttributes(url, mobileDevicesPages), "Table", "Table", true}
            }
        ),
        navTable = Table.ToNavigationTable(source, {"Name"}, "Name", "Data", "ItemKind", "ItemName", "IsLeaf")
    in
        navTable;

validateUrlScheme = (url as text) as text =>
    if (Uri.Parts(url)[Scheme] <> "https") then
        error "Url scheme must be HTTPS"
    else
        removeTrailingSlash(url);

removeTrailingSlash = (url as text) as text =>
    if Text.EndsWith(url, "/") then
        Text.RemoveRange(url, Text.Length(url) - 1, 1)
    else
        url;

getTotalNumberOfPages = (url as text, relativePath as text) as number =>
    let
        totalCount = UAPIResource(
            url, "api/" & relativePath, [#"page-size" = Text.From(PAGE_SIZE)]
        )[totalCount],
        pages = if totalCount = 0 then 0 else Number.RoundUp(totalCount / PAGE_SIZE)
    in
        pages;

getPageComputers = (url as text, sections as list, page as number) as list =>
    getPage(url, sections, page, "api/v4/computers-inventory", "id");

getPageMobileDevices = (url as text, sections as list, page as number) as list =>
    getPage(url, sections, page, "api/v2/mobile-devices/detail", "mobileDeviceId");

getPage = (url as text, sections as list, page as number, path as text, sortKey as text) as list =>
    let
        result = UAPIResource(
            url,
            path,
            [
                #"page-size" = Text.From(PAGE_SIZE),
                page = Text.From(page),
                section = sections,
                sort = sortKey
            ]
        )[results]
    in
        result;

buildPagedQuery = (page as number, optional sort as nullable text) as record =>
    if sort = null then
        [#"page-size" = Text.From(PAGE_SIZE), page = Text.From(page)]
    else
        [#"page-size" = Text.From(PAGE_SIZE), page = Text.From(page), sort = sort];

getPagedResourceResults = (url as text, relativePath as text, optional sort as nullable text) as list =>
    let
        firstPage = try UAPIResource(url, relativePath, buildPagedQuery(0, sort)) otherwise null,
        firstResults = if firstPage = null then {} else (try firstPage[results] as list otherwise {}),
        totalCount = if firstPage = null then 0 else (try Number.From(firstPage[totalCount]) otherwise List.Count(firstResults)),
        totalPages = if totalCount = 0 then 0 else Number.RoundUp(totalCount / PAGE_SIZE),
        otherPages =
            if totalPages <= 1 then
                {}
            else
                List.Transform(
                    {1..totalPages - 1},
                    each
                        try UAPIResource(url, relativePath, buildPagedQuery(_, sort))[results]
                        otherwise
                            {}
                ),
        result = List.Combine({firstResults} & otherPages)
    in
        result;

patchReleaseDateToDate = (releaseDate as nullable text) as nullable date =>
    let
        parsedDateTime =
            if releaseDate = null or releaseDate = "-1" then
                null
            else
                let
                    normalized = Text.Replace(releaseDate, " ", "T"),
                    parsed = try DateTime.FromText(normalized) otherwise try DateTime.FromText(releaseDate) otherwise null
                in
                    parsed,
        parsedDate = if parsedDateTime = null then null else DateTime.Date(parsedDateTime)
    in
        parsedDate;

getPatchDefinitions = (url as text, configurationId as text) as list =>
    getPagedResourceResults(url, "api/v3/patch-software-title-configurations/" & configurationId & "/definitions", "absoluteOrderId:asc");

getPatchReportRows = (url as text, configurationId as text) as list =>
    getPagedResourceResults(url, "api/v3/patch-software-title-configurations/" & configurationId & "/patch-report", "computerName:asc");

// Modern Jamf Pro API implementation for Mobile Device Groups
mobileDeviceGroups = (url as text) as table =>
    let
        jsonDeviceGroups = UAPIResource(url, "api/v1/mobile-device-groups"),
        deviceGroups = Table.FromRecords(jsonDeviceGroups[results]),
        selectedColumns = Table.SelectColumns(deviceGroups, {"id", "name", "isSmart"}),
        groupsPlusMembership = Table.AddColumn(
            selectedColumns,
            "temp_column",
            each getMobileDeviceMembership(Number.From([id]), [isSmart], url),
            type list
        ),
        tempTable = Table.ExpandListColumn(groupsPlusMembership, "temp_column"),
        mobileDeviceGroupExpanded = Table.ExpandRecordColumn(
            tempTable,
            "temp_column",
            {"id", "name", "macAddress", "udid", "wifiMacAddress", "serialNumber"},
            {
                "device_id",
                "device_name",
                "device_mac_address",
                "device_udid",
                "device_wifi_mac_address",
                "device_serial_number"
            }
        )
    in
        mobileDeviceGroupExpanded;

// Modern Jamf Pro API implementation for Computer Groups
computerGroups = (url as text) as table =>
    let
        jsonComputerGroups = UAPIResource(url, "api/v1/computer-groups"),
        computerGroups = Table.FromRecords(jsonComputerGroups[results]),
        selectedColumns = Table.SelectColumns(computerGroups, {"id", "name", "isSmart"}),
        computerGroupsModified = Table.AddColumn(
            selectedColumns,
            "temp_column",
            each getComputerGroupMembershipIds(Number.From([id]), [isSmart], url),
            type list
        ),
        tempTable = Table.ExpandListColumn(computerGroupsModified, "temp_column"),
        computerGroupsModifiedExpanded = Table.ExpandRecordColumn(
            tempTable,
            "temp_column",
            {"id", "name"},
            {"computer_id", "computer_name"}
        )
    in
        computerGroupsModifiedExpanded;

getComputerGroupMembershipIds = (id as number, isSmart as logical, baseUrl as text) as list =>
    let
        relativePath =
            if isSmart then
                "api/v2/computer-groups/smart-groups/" & Number.ToText(id)
            else
                "api/v2/computer-groups/static-groups/" & Number.ToText(id),
        jsonGroupDetails = try UAPIResource(baseUrl, relativePath) otherwise [],
        computerGroupMembers = try jsonGroupDetails[computers] as list otherwise {}
    in
        computerGroupMembers;

getMobileDeviceMembership = (id as number, isSmart as logical, baseUrl as text) as list =>
    let
        relativePath =
            if isSmart then
                "api/v1/mobile-device-groups/smart-groups/" & Number.ToText(id)
            else
                "api/v1/mobile-device-groups/static-groups/" & Number.ToText(id),
        jsonGroupDetails = try UAPIResource(baseUrl, relativePath) otherwise [],
        mobileDeviceGroupMembers = try jsonGroupDetails[mobileDevices] as list otherwise {}
    in
        mobileDeviceGroupMembers;

// Primary API call function for modern Jamf Pro API endpoints
UAPIResource = (
    baseUrl as text,
    relativepath as text,
    optional query as record,
    optional token as text,
    optional attempts as number
) =>
    let
        number_of_attempts = if attempts = null then 1 else (attempts + 1),
        response =
            if token = null then
                Web.Contents(
                    baseUrl,
                    [
                        Headers = [
                            #"Accept" = "application/json",
                            #"Authorization" = TokenAuthorizationHeader(baseUrl)
                        ],
                        RelativePath = relativepath,
                        ManualStatusHandling = {429, 401},
                        IsRetry = attempts <> null,
                        Query = query
                    ]
                )
            else
                Web.Contents(
                    baseUrl,
                    [
                        Headers = [
                            #"Accept" = "application/json",
                            #"Authorization" = token
                        ],
                        RelativePath = relativepath,
                        Timeout = Duration.FromText("01:00:00.0"),
                        ManualStatusHandling = {429, 401},
                        IsRetry = attempts <> null,
                        Query = query
                    ]
                ),
        responseMetadata = Value.Metadata(response),
        responseCode = responseMetadata[Response.Status],
        responseHeaders = responseMetadata[Headers],
        json =
            if responseCode <> 200 and number_of_attempts < 3 then
                Function.InvokeAfter(
                    () =>
                        @UAPIResource(
                            baseUrl,
                            relativepath,
                            query,
                            TokenAuthorizationHeader(baseUrl, true),
                            number_of_attempts
                        ),
                    #duration(0, 0, 0, 3)
                )
            else
                Json.Document(response)
    in
        json;

// Retrieves token for auth header in API calls.
// Supports either Jamf user credentials or API Client credentials entered as Username + Password.
TokenAuthorizationHeader = (baseUrl as text, optional isRetry as logical) =>
    let
        credentials = Extension.CurrentCredential(),
        retry = if isRetry <> null then isRetry else false,
        token =
            if credentials[AuthenticationKind] = "Key" then
                let
                    clientIdAndSecret = Text.Split(credentials[Key], ":"),
                    accessToken = Json.Document(
                        Web.Contents(
                            baseUrl,
                            [
                                Headers = [#"Content-Type" = "application/x-www-form-urlencoded"],
                                RelativePath = "/api/v1/oauth/token",
                                Content = Text.ToBinary(
                                    "client_id="
                                        & clientIdAndSecret{0}
                                        & "&client_secret="
                                        & clientIdAndSecret{1}
                                        & "&grant_type=client_credentials"
                                ),
                                IsRetry = retry
                            ]
                        )
                    )[access_token]
                in
                    accessToken
            else
                let
                    basicTokenResponse =
                        try
                            Json.Document(
                                Web.Contents(
                                    baseUrl,
                                    [
                                        Headers = [],
                                        RelativePath = "/api/v1/auth/token",
                                        Content = Text.ToBinary(""),
                                        IsRetry = retry
                                    ]
                                )
                            )
                        otherwise
                            null,
                    basicToken = try basicTokenResponse[token] otherwise null,
                    oauthTokenResponse =
                        if Value.Is(basicToken, type text) and Text.Length(basicToken) > 0 then
                            null
                        else
                            try
                                Json.Document(
                                    Web.Contents(
                                        baseUrl,
                                        [
                                            Headers = [#"Content-Type" = "application/x-www-form-urlencoded"],
                                            RelativePath = "/api/v1/oauth/token",
                                            Content = Text.ToBinary(
                                                Uri.BuildQueryString(
                                                    [
                                                        client_id = credentials[Username],
                                                        client_secret = credentials[Password],
                                                        grant_type = "client_credentials"
                                                    ]
                                                )
                                            ),
                                            IsRetry = retry
                                        ]
                                    )
                                )
                            otherwise
                                null,
                    oauthToken = try oauthTokenResponse[access_token] otherwise null,
                    selectedToken =
                        if Value.Is(basicToken, type text) and Text.Length(basicToken) > 0 then
                            basicToken
                        else if Value.Is(oauthToken, type text) and Text.Length(oauthToken) > 0 then
                            oauthToken
                        else
                            error "Unable to obtain a Jamf Pro API token with the supplied credentials."
                in
                    selectedToken,

        token_header = "Bearer " & token
    in
        token_header;

computerApplications = (url as text, totalPagesCount as number) as table =>
    let
        fieldNamesFromApi = {"name", "path", "version"},
        fieldNamesForTable = {
            "computerDetails.computerApplications.name",
            "computerDetails.computerApplications.path",
            "computerDetails.computerApplications.version"
        },
        emptyTable = #table(List.Combine({{"id"}, fieldNamesForTable}), {}),
        result =
            if totalPagesCount = 0 then
                emptyTable
            else
                let
                    pages = {0..totalPagesCount - 1},
                    listOfPages = List.Transform(
                        pages, each getPageComputers(url, {"GENERAL", "APPLICATIONS"}, _)
                    ),
                    rowPerComputer = List.Combine(listOfPages),
                    data = Table.FromRecords(rowPerComputer),
                    selectedColumns = Table.SelectColumns(data, {"id", "general", "applications"}),
                    expandGeneral = Table.ExpandRecordColumn(selectedColumns, "general", {"name"}),
                    expandApplications = Table.ExpandListColumn(expandGeneral, "applications"),
                    expandedApplicationsWithFieldNames = Table.ExpandRecordColumn(
                        expandApplications, "applications", fieldNamesFromApi, fieldNamesForTable
                    )
                in
                    expandedApplicationsWithFieldNames
    in
        result;

// Computer lookup and mapping function.
computers = (url as text, totalPagesCount as number) as table =>
    let
        apiFieldsTopLevel = {"id", "udid", "general", "diskEncryption", "purchasing", "userAndLocation", "hardware", "security", "operatingSystem"},
        tableFieldsTopLevel = {"id", "computerDetails.udid"},
        additionalSectionSources = List.Transform(ComputerMappings[AdditionalSectionJsonFields], each _[source]),
        emptyTable = #table(
            List.Combine(
                {
                    tableFieldsTopLevel,
                    ComputerMappings[General][mapped],
                    List.Transform(ComputerMappings[AdditionalSectionJsonFields], each _[mapped])
                }
            ),
            {}
        ),
        result =
            if totalPagesCount = 0 then
                emptyTable
            else
                let
                    pages = {0..totalPagesCount - 1},
                    listOfPages = List.Transform(
                        pages,
                        each
                            getPageComputers(
                                url,
                                COMPUTER_INVENTORY_SECTIONS,
                                _
                            )
                    ),
                    rowPerDevice = List.Combine(listOfPages),
                    selectedColumns = Table.FromRecords(
                        rowPerDevice,
                        List.Combine({apiFieldsTopLevel, additionalSectionSources}),
                        MissingField.UseNull
                    ),
                    renameUdid = Table.RenameColumns(selectedColumns, {{"udid", "computerDetails.udid"}}),
                    expandGeneral = Table.ExpandRecordColumn(renameUdid, "general", ComputerMappings[General][api], ComputerMappings[General][mapped]),
                    expandSite = Table.ExpandRecordColumn(expandGeneral, "site", ComputerMappings[Site][api], ComputerMappings[Site][mapped]),
                    expandEnrollmentMethod = Table.ExpandRecordColumn(expandSite, "enrollmentMethod", ComputerMappings[EnrollmentMethod][api], ComputerMappings[EnrollmentMethod][mapped]),
                    expandRemoteManagement = Table.ExpandRecordColumn(expandEnrollmentMethod, "remoteManagement", ComputerMappings[RemoteManagement][api], ComputerMappings[RemoteManagement][mapped]),
                    expandMdmCapable = Table.ExpandRecordColumn(expandRemoteManagement, "mdmCapable", ComputerMappings[MdmCapable][api], ComputerMappings[MdmCapable][mapped]),
                    expandPurchasing = Table.ExpandRecordColumn(expandMdmCapable, "purchasing", ComputerMappings[Purchasing][api], ComputerMappings[Purchasing][mapped]),
                    expandUserAndLocation = Table.ExpandRecordColumn(expandPurchasing, "userAndLocation", ComputerMappings[UserAndLocation][api], ComputerMappings[UserAndLocation][mapped]),
                    expandHardware = Table.ExpandRecordColumn(expandUserAndLocation, "hardware", ComputerMappings[Hardware][api], ComputerMappings[Hardware][mapped]),
                    expandSecurity = Table.ExpandRecordColumn(expandHardware, "security", ComputerMappings[Security][api], ComputerMappings[Security][mapped]),
                    expandOperatingSystem = Table.ExpandRecordColumn(expandSecurity, "operatingSystem", ComputerMappings[OperatingSystem][api], ComputerMappings[OperatingSystem][mapped]),
                    expandDiskEncryption = Table.ExpandRecordColumn(expandOperatingSystem, "diskEncryption", ComputerMappings[DiskEncryption][api], ComputerMappings[DiskEncryption][mapped]),

                    // Add legacy unmapped columns, calculate numeric epoch columns, and duplicate aliased fields
                    withUnmappedColumns = addUnmappedColumns(expandDiskEncryption, ComputerMappings[UnmappedFields]),
                    withEpochColumns = copyUtcColumnsToEpoch(withUnmappedColumns, ComputerMappings[UtcColumnNames]),
                    withDuplicateColumns = duplicateColumns(withEpochColumns, ComputerMappings[FieldsToDuplicate]),
                    withNormalisedSectionColumns = normaliseNestedColumns(withDuplicateColumns),
                    withRenamedSectionColumns = renameFlattenedSectionColumns(withNormalisedSectionColumns, ComputerMappings[AdditionalSectionJsonFields])
                in
                    withRenamedSectionColumns
    in
        result;

computerStorage = (url as text, totalPagesCount as number) as table =>
    let
        emptyTable = #table({"id", "computer_name", "computerDetails.storage_json"}, {}),
        result =
            if totalPagesCount = 0 then
                emptyTable
            else
                let
                    pages = {0..totalPagesCount - 1},
                    listOfPages = List.Transform(
                        pages,
                        each getPageComputers(url, {"GENERAL", "STORAGE"}, _)
                    ),
                    rowPerDevice = List.Combine(listOfPages),
                    selectedColumns = Table.FromRecords(
                        rowPerDevice,
                        {"id", "general", "storage"},
                        MissingField.UseNull
                    ),
                    expandGeneral = Table.ExpandRecordColumn(selectedColumns, "general", {"name"}, {"computer_name"}),
                    renameStorage = Table.RenameColumns(expandGeneral, {{"storage", "storageSection"}}, MissingField.Ignore),
                    normalised = normaliseNestedColumns(renameStorage),
                    renamed = renameFlattenedSectionColumns(normalised, {[source = "storageSection", mapped = "computerDetails.storage_json"]})
                in
                    renamed
    in
        result;

computerPatchStatus = (url as text) as table =>
    let
        columnNames = {
            "patch_configuration_id",
            "patch_display_name",
            "software_title_id",
            "software_title_name",
            "software_title_publisher",
            "site_id",
            "computer_id",
            "computer_name",
            "username",
            "operating_system_version",
            "last_check_in_utc",
            "building_name",
            "department_name",
            "site_name",
            "installed_version",
            "version_release_date",
            "days_since_version_release",
            "more_than_30_days_since_release"
        },
        emptyTable = #table(columnNames, {}),
        patchConfigurations = try UAPIResource(url, "api/v3/patch-software-title-configurations") otherwise {},
        configurationRows = if Value.Is(patchConfigurations, type list) then patchConfigurations else {},
        patchRowsByConfiguration = List.Transform(
            configurationRows,
            (configuration) =>
                let
                    configurationId = try Text.From(configuration[id]) otherwise null,
                    definitions = if configurationId = null then {} else getPatchDefinitions(url, configurationId),
                    reportRows = if configurationId = null then {} else getPatchReportRows(url, configurationId),
                    reportRowsEnriched = List.Transform(
                        reportRows,
                        (reportRow) =>
                            let
                                installedVersion = try Text.From(reportRow[version]) otherwise null,
                                matchingDefinition =
                                    List.First(
                                        List.Select(
                                            definitions,
                                            each (try Text.From(_[version]) otherwise null) = installedVersion
                                        ),
                                        null
                                    ),
                                releaseDateText = if matchingDefinition = null then null else (try Text.From(matchingDefinition[releaseDate]) otherwise null),
                                releaseDate = patchReleaseDateToDate(releaseDateText),
                                daysSinceRelease = if releaseDate = null then null else Duration.Days(Date.From(DateTime.LocalNow()) - releaseDate),
                                moreThanThirtyDays = if daysSinceRelease = null then null else daysSinceRelease > 30
                            in
                                [
                                    patch_configuration_id = configurationId,
                                    patch_display_name = try Text.From(configuration[displayName]) otherwise null,
                                    software_title_id = try Text.From(configuration[softwareTitleId]) otherwise null,
                                    software_title_name = try Text.From(configuration[softwareTitleName]) otherwise null,
                                    software_title_publisher = try Text.From(configuration[softwareTitlePublisher]) otherwise null,
                                    site_id = try Text.From(configuration[siteId]) otherwise null,
                                    computer_id = try Text.From(reportRow[deviceId]) otherwise null,
                                    computer_name = try Text.From(reportRow[computerName]) otherwise null,
                                    username = try Text.From(reportRow[username]) otherwise null,
                                    operating_system_version = try Text.From(reportRow[operatingSystemVersion]) otherwise null,
                                    last_check_in_utc = try DateTimeZone.FromText(reportRow[lastCheckIn]) otherwise null,
                                    building_name = try Text.From(reportRow[buildingName]) otherwise null,
                                    department_name = try Text.From(reportRow[departmentName]) otherwise null,
                                    site_name = try Text.From(reportRow[siteName]) otherwise null,
                                    installed_version = installedVersion,
                                    version_release_date = releaseDate,
                                    days_since_version_release = daysSinceRelease,
                                    more_than_30_days_since_release = moreThanThirtyDays
                                ]
                    )
                in
                    reportRowsEnriched
        ),
        patchRows = List.Combine(patchRowsByConfiguration),
        result =
            if List.Count(patchRows) = 0 then
                emptyTable
            else
                Table.FromRecords(patchRows, columnNames, MissingField.UseNull)
    in
        result;

// Mobile device lookup and mapping function.
mobileDevices = (url as text, totalPagesCount as number) as table =>
    let
        apiFieldsTopLevel = {"mobileDeviceId", "deviceType", "general", "hardware", "userAndLocation", "security", "purchasing", "network"},
        tableFieldsTopLevel = {"id", "mobileDeviceDetails.os_type"},
        additionalSectionSources = List.Transform(MobileDeviceMappings[AdditionalSectionJsonFields], each _[source]),

        emptyTable = #table(
            List.Combine(
                {
                    tableFieldsTopLevel,
                    MobileDeviceMappings[General][mapped],
                    MobileDeviceMappings[Hardware][mapped],
                    MobileDeviceMappings[UserAndLocation][mapped],
                    MobileDeviceMappings[Security][mapped],
                    MobileDeviceMappings[LostModeLocation][mapped],
                    MobileDeviceMappings[Purchasing][mapped],
                    MobileDeviceMappings[Network][mapped],
                    List.Transform(MobileDeviceMappings[AdditionalSectionJsonFields], each _[mapped])
                }
            ),
            {}
        ),
        result =
            if totalPagesCount = 0 then
                emptyTable
            else
                let
                    pages = {0..totalPagesCount - 1},
                    listOfPages = List.Transform(
                        pages,
                        each
                            getPageMobileDevices(
                                url, MOBILE_DEVICE_INVENTORY_SECTIONS, _
                            )
                    ),
                    rowPerDevice = List.Combine(listOfPages),
                    selectedColumns = Table.FromRecords(
                        rowPerDevice,
                        List.Combine({apiFieldsTopLevel, additionalSectionSources}),
                        MissingField.UseNull
                    ),
                    renameTopLevelFields = Table.RenameColumns(selectedColumns, List.Zip({apiFieldsTopLevel, tableFieldsTopLevel})),
                    expandGeneral = Table.ExpandRecordColumn(renameTopLevelFields, "general", MobileDeviceMappings[General][api], MobileDeviceMappings[General][mapped]),
                    expandHardware = Table.ExpandRecordColumn(expandGeneral, "hardware", MobileDeviceMappings[Hardware][api], MobileDeviceMappings[Hardware][mapped]),
                    expandUserAndLocation = Table.ExpandRecordColumn(expandHardware, "userAndLocation", MobileDeviceMappings[UserAndLocation][api], MobileDeviceMappings[UserAndLocation][mapped]),
                    expandSecurity = Table.ExpandRecordColumn(expandUserAndLocation, "security", MobileDeviceMappings[Security][api], MobileDeviceMappings[Security][mapped]),
                    expandLostModeLocation = Table.ExpandRecordColumn(expandSecurity, "lostModeLocation", MobileDeviceMappings[LostModeLocation][api], MobileDeviceMappings[LostModeLocation][mapped]),
                    expandPurchasing = Table.ExpandRecordColumn(expandLostModeLocation, "purchasing", MobileDeviceMappings[Purchasing][api], MobileDeviceMappings[Purchasing][mapped]),
                    expandNetwork = Table.ExpandRecordColumn(expandPurchasing, "network", MobileDeviceMappings[Network][api], MobileDeviceMappings[Network][mapped])
                in
                    expandNetwork,

        withUnmappedColumns = addUnmappedColumns(result, MobileDeviceMappings[UnmappedFields]),
        withEpochColumns = copyUtcColumnsToEpoch(withUnmappedColumns, MobileDeviceMappings[UtcColumnNames]),
        withDuplicateColumns = duplicateColumns(withEpochColumns, MobileDeviceMappings[FieldsToDuplicate]),
        withNormalisedSectionColumns = normaliseNestedColumns(withDuplicateColumns),
        withRenamedSectionColumns = renameFlattenedSectionColumns(withNormalisedSectionColumns, MobileDeviceMappings[AdditionalSectionJsonFields])
    in
        withRenamedSectionColumns;

mobileDeviceApplications = (url as text, totalPagesCount as number) as table =>
    let
        apiFieldsGeneral = {"displayName", "udid", "managed", "supervised"},
        tableFieldsGeneral = {"name", "udid", "managed", "supervised"},
        apiFieldsHardware = {"serialNumber", "wifiMacAddress", "model", "modelIdentifier"},
        tableFieldsHardware = {"serial_number", "wifi_mac_address", "model", "model_identifier"},
        apiFieldsApps = {"name", "version", "identifier"},
        tableFieldsApps = {
            "mobileDeviceDetails.mdApps.application_name",
            "mobileDeviceDetails.mdApps.application_version",
            "mobileDeviceDetails.mdApps.identifier"
        },
        apiFieldsUserAndLocation = {"phoneNumber", "username"},
        tableFieldsUserAndLocation = {"phone_number", "username"},
        emptyTable = #table(
            List.Combine(
                {{"id"}, tableFieldsGeneral, tableFieldsHardware, tableFieldsUserAndLocation, tableFieldsApps}
            ),
            {}
        ),
        result =
            if totalPagesCount = 0 then
                emptyTable
            else
                let
                    pages = {0..totalPagesCount - 1},
                    listOfPages = List.Transform(
                        pages,
                        each
                            getPageMobileDevices(url, {"GENERAL", "APPLICATIONS", "HARDWARE", "USER_AND_LOCATION"}, _)
                    ),
                    rowPerDevice = List.Combine(listOfPages),
                    selectedColumns = Table.FromRecords(
                        rowPerDevice,
                        {"mobileDeviceId", "general", "hardware", "userAndLocation", "applications"},
                        MissingField.UseNull
                    ),
                    renameIdField = Table.RenameColumns(selectedColumns, {{"mobileDeviceId", "id"}}),
                    expandGeneral = Table.ExpandRecordColumn(renameIdField, "general", apiFieldsGeneral, tableFieldsGeneral),
                    expandHardware = Table.ExpandRecordColumn(expandGeneral, "hardware", apiFieldsHardware, tableFieldsHardware),
                    expandUserAndLocation = Table.ExpandRecordColumn(expandHardware, "userAndLocation", apiFieldsUserAndLocation, tableFieldsUserAndLocation),
                    normalizeApps = Table.ExpandListColumn(expandUserAndLocation, "applications"),
                    expandApps = Table.ExpandRecordColumn(normalizeApps, "applications", apiFieldsApps, tableFieldsApps)
                in
                    expandApps,
        
        withDuplicateColumns = duplicateColumns(result, MobileDeviceMappings[AppsAndEAsFieldsToDuplicate])
    in
        withDuplicateColumns;

computerExtensionAttributes = (url as text, totalPagesCount as number) as table =>
    let
        fieldNamesForTable = {"computerDetails.extAttrs.id", "computerDetails.extAttrs.name", "computerDetails.extAttrs.type", "computerDetails.extAttrs.value"},
        emptyTable = #table(List.Combine({{"id", "name"}, fieldNamesForTable}), {}),
        result =
            if totalPagesCount = 0 then
                emptyTable
            else
                let
                    pages = {0..totalPagesCount - 1},
                    listOfPages = List.Transform(
                        pages, each getPageComputers(
                            url, {"GENERAL", "HARDWARE", "USER_AND_LOCATION", "PURCHASING", "OPERATING_SYSTEM", "EXTENSION_ATTRIBUTES"}, _
                        )
                    ),
                    rowPerComputer = List.Combine(listOfPages),
                    data = Table.FromRecords(rowPerComputer),
                    selectedColumns = Table.SelectColumns(data, {"id", "general", "hardware", "userAndLocation", "purchasing", "operatingSystem", "extensionAttributes"}),

                    expandGeneral = Table.ExpandRecordColumn(selectedColumns, "general", {"name", "extensionAttributes"}, {"name", "general.extensionAttributes"}),
                    expandHardware = Table.ExpandRecordColumn(expandGeneral, "hardware", {"extensionAttributes"}, {"hardware.extensionAttributes"}),
                    expandUserAndLocation = Table.ExpandRecordColumn(expandHardware, "userAndLocation", {"extensionAttributes"}, {"userAndLocation.extensionAttributes"}),
                    expandPurchasing = Table.ExpandRecordColumn(expandUserAndLocation, "purchasing", {"extensionAttributes"}, {"purchasing.extensionAttributes"}),
                    expandOperatingSystem = Table.ExpandRecordColumn(expandPurchasing, "operatingSystem", {"extensionAttributes"}, {"operatingSystem.extensionAttributes"}),

                    eaApiFields = [id = "definitionId", name = "name", dataType = "dataType", value = "values"],
                    eaTableFields = [id = "computerDetails.extAttrs.id", name = "computerDetails.extAttrs.name", dataType = "computerDetails.extAttrs.type", value = "computerDetails.extAttrs.value"],
                    generalNormalized = normalizeEAs(expandOperatingSystem, "general.extensionAttributes", eaApiFields, eaTableFields),
                    hardwareNormalized = normalizeEAs(expandOperatingSystem, "hardware.extensionAttributes", eaApiFields, eaTableFields),
                    userAndLocationNormalized = normalizeEAs(expandOperatingSystem, "userAndLocation.extensionAttributes", eaApiFields, eaTableFields),
                    purchasingNormalized = normalizeEAs(expandOperatingSystem, "purchasing.extensionAttributes", eaApiFields, eaTableFields),
                    operatingSystemNormalized = normalizeEAs(expandOperatingSystem, "operatingSystem.extensionAttributes", eaApiFields, eaTableFields),
                    extensionAttributesNormalized = normalizeEAs(expandOperatingSystem, "extensionAttributes", eaApiFields, eaTableFields),
                    combinedEAs = Table.Combine({generalNormalized, hardwareNormalized, userAndLocationNormalized, purchasingNormalized, operatingSystemNormalized, extensionAttributesNormalized}),

                    finalColumns = Table.SelectColumns(combinedEAs, List.Combine({{"id", "name"}, fieldNamesForTable}))
                in
                    finalColumns
    in
        result;

mobileDeviceExtensionAtttributes = (url as text, totalPagesCount as number) as table =>
    let
        apiFieldsGeneral = {"displayName", "udid", "managed", "supervised", "extensionAttributes"},
        tableFieldsGeneral = {"name", "udid", "managed", "supervised", "general.extensionAttributes"},
        apiFieldsHardware = {"serialNumber", "wifiMacAddress", "model", "modelIdentifier", "extensionAttributes"},
        tableFieldsHardware = {"serial_number", "wifi_mac_address", "model", "model_identifier", "hardware.extensionAttributes"},
        apiFieldsUserAndLocation = {"phoneNumber", "username", "extensionAttributes"},
        tableFieldsUserAndLocation = {"phone_number", "username", "userAndLocation.extensionAttributes"},

        eaFieldNames = {"ExtAttrId", "ExtAttrName", "ExtAttrType", "ExtAttrVal"},
        finalColumnNames = List.Combine(
            {
                {"id"},
                List.RemoveItems(tableFieldsGeneral, {"general.extensionAttributes"}),
                List.RemoveItems(tableFieldsHardware, {"hardware.extensionAttributes"}),
                List.RemoveItems(tableFieldsUserAndLocation, {"userAndLocation.extensionAttributes"}),
                eaFieldNames
            }
        ),

        emptyTable = #table(finalColumnNames, {}),
        result =
            if totalPagesCount = 0 then
                emptyTable
            else
                let
                    pages = {0..totalPagesCount - 1},
                    listOfPages = List.Transform(
                        pages,
                        each
                            getPageMobileDevices(url, {"GENERAL", "HARDWARE", "USER_AND_LOCATION", "PURCHASING", "EXTENSION_ATTRIBUTES"}, _)
                    ),
                    rowPerDevice = List.Combine(listOfPages),
                    selectedColumns = Table.FromRecords(
                        rowPerDevice,
                        {"mobileDeviceId", "general", "hardware", "userAndLocation", "purchasing", "extensionAttributes"},
                        MissingField.UseNull
                    ),
                    renameIdField = Table.RenameColumns(selectedColumns, {{"mobileDeviceId", "id"}}),
                    expandGeneral = Table.ExpandRecordColumn(renameIdField, "general", apiFieldsGeneral, tableFieldsGeneral),
                    expandHardware = Table.ExpandRecordColumn(expandGeneral, "hardware", apiFieldsHardware, tableFieldsHardware),
                    expandUserAndLocation = Table.ExpandRecordColumn(expandHardware, "userAndLocation", apiFieldsUserAndLocation, tableFieldsUserAndLocation),
                    expandPurchasing = Table.ExpandRecordColumn(expandUserAndLocation, "purchasing", {"extensionAttributes"}, {"purchasing.extensionAttributes"}),

                    eaApiFields = [id = "id", name = "name", dataType = "type", value = "value"],
                    eaTableFields = [id = "ExtAttrId", name = "ExtAttrName", dataType = "ExtAttrType", value = "ExtAttrVal"],
                    generalNormalized = normalizeEAs(expandPurchasing, "general.extensionAttributes", eaApiFields, eaTableFields),
                    userAndLocationNormalized = normalizeEAs(expandPurchasing, "userAndLocation.extensionAttributes", eaApiFields, eaTableFields),
                    hardwareNormalized = normalizeEAs(expandPurchasing, "hardware.extensionAttributes", eaApiFields, eaTableFields),
                    purchasingNormalized = normalizeEAs(expandPurchasing, "purchasing.extensionAttributes", eaApiFields, eaTableFields),
                    extensionAttributesNormalized = normalizeEAs(expandPurchasing, "extensionAttributes", eaApiFields, eaTableFields),
                    combinedEAs = Table.Combine({generalNormalized, userAndLocationNormalized, hardwareNormalized, purchasingNormalized, extensionAttributesNormalized})
                in
                    combinedEAs,

        finalUniqueColumns = Table.SelectColumns(result, finalColumnNames),
        withDuplicateColumns = duplicateColumns(finalUniqueColumns, MobileDeviceMappings[AppsAndEAsFieldsToDuplicate])
    in
        withDuplicateColumns;

normalizeEAs = (t as table, columnName as text, apiFields as record, tableFields as record) as table =>
    let
        normalizeEAs = Table.ExpandListColumn(t, columnName),
        expandEAs = Table.ExpandRecordColumn(
            normalizeEAs,
            columnName,
            {apiFields[id],     apiFields[name],    apiFields[dataType],    apiFields[value]},
            {tableFields[id],   tableFields[name],  tableFields[dataType],  tableFields[value]}
        ),
        expandValues = Table.ExpandListColumn(expandEAs, tableFields[value]),
        filteredEAs = Table.SelectRows(expandValues, each Record.Field(_, tableFields[id]) <> null),
        result = Table.RemoveColumns(filteredEAs, {columnName}, MissingField.Ignore)
    in
        result;

dateStringIso8601ToEpochMillis = (dateString as text) as number =>
    let
        dateObject = DateTime.FromText(dateString),
        epochMillis = Duration.TotalSeconds(Duration.From(dateObject - #datetime(1970, 1, 1, 0, 0, 0))) * 1000
    in
        epochMillis;

copyUtcColumnsToEpoch = (t as table, utcColumnNames as list) as table =>
    let
        epochColumnNames = List.Transform(utcColumnNames, each Text.Replace(_, "_utc", "_epoch")),
        addEpochColumns = List.Accumulate(
            List.Zip({utcColumnNames, epochColumnNames}),
            t,
            (state, current) =>
                let
                    utcColumnName = current{0},
                    epochColumnName = current{1},
                    addColumn = Table.AddColumn(state, epochColumnName, each try dateStringIso8601ToEpochMillis(Record.Field(_, utcColumnName)) otherwise 0, type number)
                in
                    addColumn
        )
    in
        addEpochColumns;

columnContainsType = (columnValues as list, valueType as type) as logical =>
    List.AnyTrue(List.Transform(columnValues, each _ <> null and Value.Is(_, valueType)));

expandRecordColumns = (t as table) as table =>
    let
        recordColumns = List.Select(
            Table.ColumnNames(t),
            each columnContainsType(Table.Column(t, _), type record)
        ),
        result = List.Accumulate(
            recordColumns,
            t,
            (state, current) =>
                let
                    recordValues = List.Select(Table.Column(state, current), each _ <> null and Value.Is(_, type record)),
                    fieldNames = List.Sort(List.Union(List.Transform(recordValues, each Record.FieldNames(_))))
                in
                    if List.Count(fieldNames) = 0 then
                        state
                    else
                        Table.ExpandRecordColumn(
                            state,
                            current,
                            fieldNames,
                            List.Transform(fieldNames, each current & "." & _)
                        )
        )
    in
        result;

expandRecordsRecursively = (t as table) as table =>
    let
        expanded = expandRecordColumns(t),
        madeProgress = not List.Equals(Table.ColumnNames(expanded), Table.ColumnNames(t)),
        hasRecordColumns = List.AnyTrue(
            List.Transform(
                Table.ColumnNames(expanded),
                each columnContainsType(Table.Column(expanded, _), type record)
            )
        ),
        result = if hasRecordColumns and madeProgress then @expandRecordsRecursively(expanded) else expanded
    in
        result;

normaliseNestedColumns = (t as table) as table =>
    let
        expanded = expandRecordsRecursively(t),
        complexColumns = List.Select(
            Table.ColumnNames(expanded),
            each
                columnContainsType(Table.Column(expanded, _), type list)
                    or columnContainsType(Table.Column(expanded, _), type record)
        ),
        result = List.Accumulate(
            complexColumns,
            expanded,
            (state, current) =>
                Table.TransformColumns(
                    state,
                    {{current, each if _ = null then null else Text.FromBinary(Json.FromValue(_)), type nullable text}}
                )
        )
    in
        result;

renameFlattenedSectionColumns = (t as table, sectionMappings as list) as table =>
    let
        renamePairs = List.Combine(
            List.Transform(
                sectionMappings,
                (mapping) =>
                    let
                        sourceName = mapping[source],
                        mappedName = mapping[mapped],
                        mappedPrefix = Text.BeforeDelimiter(mappedName, "_json"),
                        sourceColumns = List.Select(
                            Table.ColumnNames(t),
                            each _ = sourceName or Text.StartsWith(_, sourceName & ".")
                        ),
                        pairs = List.Transform(
                            sourceColumns,
                            each
                                {
                                    _,
                                    if _ = sourceName then
                                        mappedName
                                    else
                                        mappedPrefix & "." & Text.Range(_, Text.Length(sourceName) + 1)
                                }
                        )
                    in
                        pairs
            )
        ),
        result = Table.RenameColumns(t, renamePairs, MissingField.Ignore)
    in
        result;

addUnmappedColumns = (t as table, unmappedFields as list) as table =>
    let
        result = List.Accumulate(
            unmappedFields,
            t,
            (state, current) =>
                try
                    Table.AddColumn(state, current, each null, type any)
                otherwise
                    state
        )
    in
        result;

duplicateColumns = (t as table, fieldsToDuplicate as list) as table =>
    let
        result = List.Accumulate(
            fieldsToDuplicate,
            t,
            (state, current) =>
                let
                    addColumn = Table.AddColumn(state, current[duplicate], each Record.Field(_, current[original]), type any)
                in
                    addColumn
        )
    in
        result;

// Data Source definition
JamfPro = [
    TestConnection = (dataSourcePath) => {"JamfPro.JamfNavTable", dataSourcePath},
    Authentication = [
        UsernamePassword = [
            Label = Extension.LoadString("AuthLabelUsernamePassword")
        ]
    ],
    Label = Extension.LoadString("DataSourceLabel")
];

// Data Source UI publishing description
JamfPro.Publish = [
    Beta = false,
    Category = "Other",
    ButtonText = {Extension.LoadString("ButtonTitle"), Extension.LoadString("ButtonHelp")},
    LearnMoreUrl = "https://marketplace.jamf.com/details/power-bi",
    SourceImage = JamfPro__Get_Devices.Icons,
    SourceTypeImage = JamfPro__Get_Devices.Icons
];

JamfPro__Get_Devices.Icons = [
    Icon16 = {
        Extension.Contents("JamfPro16.png"),
        Extension.Contents("JamfPro20.png"),
        Extension.Contents("JamfPro24.png"),
        Extension.Contents("JamfPro32.png")
    },
    Icon32 = {
        Extension.Contents("JamfPro32.png"),
        Extension.Contents("JamfPro40.png"),
        Extension.Contents("JamfPro48.png"),
        Extension.Contents("JamfPro64.png")
    }
];

Table.ToNavigationTable = (
    table as table,
    keyColumns as list,
    nameColumn as text,
    dataColumn as text,
    itemKindColumn as text,
    itemNameColumn as text,
    isLeafColumn as text
) as table =>
    let
        tableType = Value.Type(table),
        newTableType = Type.AddTableKey(tableType, keyColumns, true) meta [
            NavigationTable.NameColumn = nameColumn,
            NavigationTable.DataColumn = dataColumn,
            NavigationTable.ItemKindColumn = itemKindColumn,
            Preview.DelayColumn = itemNameColumn,
            NavigationTable.IsLeafColumn = isLeafColumn
        ],
        navigationTable = Value.ReplaceType(table, newTableType)
    in
        navigationTable;

Extension.LoadFunction = (fileName as text) =>
  let
      binary = Extension.Contents(fileName),
      asText = Text.FromBinary(binary)
  in
      try
        Expression.Evaluate(asText, #shared)
      catch (e) =>
        error [
            Reason = "Extension.LoadFunction Failure",
            Message.Format = "Loading '#{0}' failed - '#{1}': '#{2}'",
            Message.Parameters = {fileName, e[Reason], e[Message]},
            Detail = [File = fileName, Error = e]
        ];

MobileDeviceMappings = Extension.LoadFunction("MobileDeviceMappings.pqm");
ComputerMappings = Extension.LoadFunction("ComputerMappings.pqm");
