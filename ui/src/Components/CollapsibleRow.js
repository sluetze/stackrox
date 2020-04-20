import React, { useState } from 'react';
import PropTypes from 'prop-types';
import posed from 'react-pose';

import { ChevronRight, ChevronDown } from 'react-feather';

const Content = posed.div({
    closed: { height: 0 },
    open: { height: 'inherit' },
});

const CollapsibleRow = ({ header, isCollapsible, children, isCollapsibleOpen, hasTitleBorder }) => {
    const [open, setOpen] = useState(isCollapsibleOpen);

    function toggleOpen() {
        if (!isCollapsible) return;
        setOpen(!open);
    }

    const icons = {
        opened: (
            <ChevronDown
                className={`bg-base-200 border border-base-400 mr-4 rounded-full ${
                    !isCollapsible ? 'invisible' : ''
                }`}
                size="14"
            />
        ),
        closed: (
            <ChevronRight
                className={`bg-base-200 border border-base-400 mr-4 rounded-full ${
                    !isCollapsible ? 'invisible' : ''
                }`}
                size="14"
            />
        ),
    };

    return (
        <div className={`${hasTitleBorder ? 'border-b' : ''} border-base-300 w-full`}>
            <button
                type="button"
                className={`flex flex-1 w-full ${
                    isCollapsible ? 'cursor-pointer hover:bg-primary-100' : 'cursor-auto'
                }`}
                onClick={toggleOpen}
            >
                <div className={`flex w-full p-3 ${open ? 'border-b border-base-300' : ''}`}>
                    {icons[open ? 'opened' : 'closed']}
                    {header}
                </div>
            </button>
            <Content className="overflow-hidden" pose={open ? 'open' : 'closed'}>
                {open && children}
            </Content>
        </div>
    );
};

CollapsibleRow.propTypes = {
    header: PropTypes.node.isRequired,
    isCollapsible: PropTypes.bool,
    children: PropTypes.node.isRequired,
    isCollapsibleOpen: PropTypes.bool,
    hasTitleBorder: PropTypes.bool,
};

CollapsibleRow.defaultProps = {
    isCollapsible: true,
    isCollapsibleOpen: true,
    hasTitleBorder: true,
};

export default CollapsibleRow;
