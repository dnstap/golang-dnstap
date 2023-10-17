%global debug_package %{nil}

# https://github.com/dnstap/golang-dnstap
%global goipath         github.com/dnstap/golang-dnstap
Version:                0.4.0

%gometa

%global common_description %{expand:
Implements an encoding format for DNS server events.}

%global golicences      LICENSE
%global godocs          README

Name:           %{goname}
Release:        %autorelease
Summary:        DNS server event encoding format

License:        Apache-2.0
URL:            %{gourl}
Source0:        %{gosource}

%description
%{common_description}

%gopkg

%prep
%goprep

%generate_buildrequires
%go_generate_buildrequires

%install
%gopkginstall

%if %{with check}
%check
%gocheck
%endif

%gopkgfiles

%changelog
%autochangelog
